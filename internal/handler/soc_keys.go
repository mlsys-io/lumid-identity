package handler

// SoC LLM gateway key pool (NUS soclaas, SOCLAAS_API_KEY).
//
// Admin surface (lum.id/code "SoC API keys" panel):
//   GET    /api/v1/admin/soc-keys        list (no key material)
//   POST   /api/v1/admin/soc-keys        import {key, label?}; verified upstream first
//   DELETE /api/v1/admin/soc-keys/:id    remove from the pool
//   POST   /api/v1/admin/soc-keys/:id/reset   clear a bench (e.g. after a manual check)
//
// Internal surface (claude-proxy, X-Bridge-Secret):
//   GET  /api/v1/internal/soc-keys         every usable key, decrypted
//   POST /api/v1/internal/soc-keys/bench   {id, seconds, dead, reason} / {id, used:true}

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func socBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("SOCLAAS_BASE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://soclaas-api.comp.nus.edu.sg/v1"
}

func socKeyFP(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:16]
}

var socVerifyClient = &http.Client{Timeout: 20 * time.Second}

// verifySocKey checks the key against the gateway's /models (free, no tokens).
// Returns nil on 200; a user-facing error otherwise.
func verifySocKey(key string) error {
	req, err := http.NewRequest(http.MethodGet, socBaseURL()+"/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := socVerifyClient.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the SoC gateway: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return errors.New("the SoC gateway rejected this key (" + strings.TrimSpace(string(raw)) + ")")
	default:
		return fmt.Errorf("the SoC gateway returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
}

type socKeyView struct {
	models.SocAPIKey
	KeyHint string `json:"key_hint"`
	Status  string `json:"status"` // active | benched | dead
}

func socKeyStatus(k models.SocAPIKey, now time.Time) string {
	if k.BenchDead {
		return "dead"
	}
	if k.BenchUntil != nil && k.BenchUntil.After(now) {
		return "benched"
	}
	return "active"
}

func AdminSocKeysList(c *gin.Context) {
	var rows []models.SocAPIKey
	if err := common.DB.Order("id").Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "list soc keys: "+err.Error())
		return
	}
	now := time.Now()
	out := make([]socKeyView, 0, len(rows))
	active := 0
	for _, r := range rows {
		st := socKeyStatus(r, now)
		if st == "active" {
			active++
		}
		out = append(out, socKeyView{SocAPIKey: r, KeyHint: "…" + r.KeyFP[len(r.KeyFP)-6:], Status: st})
	}
	ok(c, "ok", gin.H{"keys": out, "total": len(out), "active": active})
}

func AdminSocKeyAdd(c *gin.Context) {
	var body struct {
		Key   string `json:"key" binding:"required"`
		Label string `json:"label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	key := strings.Trim(strings.TrimSpace(body.Key), `"'`)
	key = strings.TrimPrefix(key, "SOCLAAS_API_KEY=")
	key = strings.TrimPrefix(key, "Bearer ")
	if key == "" || strings.ContainsAny(key, " \t\r\n") || len(key) > 256 {
		fail(c, http.StatusBadRequest, 1400, "paste the bare SOCLAAS_API_KEY value")
		return
	}
	label := strings.TrimSpace(body.Label)
	if len(label) > 128 {
		label = label[:128]
	}
	if err := verifySocKey(key); err != nil {
		fail(c, http.StatusBadRequest, 1401, err.Error())
		return
	}
	enc, err := common.EncryptGrant(key)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "encrypt: "+err.Error())
		return
	}
	ownerSub, _ := currentUserID(c)
	var owner models.User
	if ownerSub != "" {
		common.DB.Select("email").Where("id = ?", ownerSub).First(&owner)
	}
	fp := socKeyFP(key)

	var row models.SocAPIKey
	err = common.DB.Where("key_fp = ?", fp).First(&row).Error
	switch {
	case err == nil:
		// Re-import of a known key: refresh ciphertext + clear any bench/dead.
		upd := map[string]interface{}{
			"key_encrypted": enc, "bench_until": nil, "bench_reason": "", "bench_dead": false,
		}
		if label != "" {
			upd["label"] = label
		}
		if err := common.DB.Model(&row).Updates(upd).Error; err != nil {
			fail(c, http.StatusInternalServerError, 1500, "update: "+err.Error())
			return
		}
		ok(c, "key already pooled — refreshed and re-enabled", gin.H{"id": row.ID, "created": false})
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		row = models.SocAPIKey{KeyFP: fp, KeyEncrypted: enc, Label: label, OwnerSub: ownerSub, OwnerEmail: owner.Email}
		if err := common.DB.Create(&row).Error; err != nil {
			fail(c, http.StatusInternalServerError, 1500, "create: "+err.Error())
			return
		}
		log.Printf("soc-pool: key %d (…%s) imported by %s", row.ID, fp[10:], owner.Email)
		ok(c, "key added to the pool", gin.H{"id": row.ID, "created": true})
	default:
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
	}
}

func socKeyByParam(c *gin.Context) (*models.SocAPIKey, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, "bad id")
		return nil, false
	}
	var row models.SocAPIKey
	if err := common.DB.First(&row, id).Error; err != nil {
		fail(c, http.StatusNotFound, 1404, "no such key")
		return nil, false
	}
	return &row, true
}

func AdminSocKeyDelete(c *gin.Context) {
	row, found := socKeyByParam(c)
	if !found {
		return
	}
	if err := common.DB.Delete(row).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "delete: "+err.Error())
		return
	}
	ok(c, "removed", gin.H{"id": row.ID})
}

func AdminSocKeyReset(c *gin.Context) {
	row, found := socKeyByParam(c)
	if !found {
		return
	}
	common.DB.Model(row).Updates(map[string]interface{}{"bench_until": nil, "bench_reason": "", "bench_dead": false})
	ok(c, "bench cleared", gin.H{"id": row.ID})
}

// InternalSocKeys hands claude-proxy every usable key (not dead, not benched).
func InternalSocKeys(c *gin.Context) {
	var rows []models.SocAPIKey
	now := time.Now()
	if err := common.DB.Where("bench_dead = ? AND (bench_until IS NULL OR bench_until < ?)", false, now).
		Order("id").Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "list: "+err.Error())
		return
	}
	type item struct {
		ID  uint   `json:"id"`
		Key string `json:"key"`
	}
	out := make([]item, 0, len(rows))
	for _, r := range rows {
		k, err := common.DecryptGrant(r.KeyEncrypted)
		if err != nil {
			log.Printf("soc-pool: key %d undecryptable, skipping: %v", r.ID, err)
			continue
		}
		out = append(out, item{ID: r.ID, Key: k})
	}
	ok(c, "ok", gin.H{"keys": out})
}

// InternalSocKeyBench persists a proxy verdict on one key: a bench (daily limit
// → until the reset; dead → until re-import), or `used` to stamp last_used_at.
func InternalSocKeyBench(c *gin.Context) {
	var body struct {
		ID      uint   `json:"id"`
		Seconds int    `json:"seconds"`
		Dead    bool   `json:"dead"`
		Used    bool   `json:"used"`
		Reason  string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.ID == 0 {
		fail(c, http.StatusBadRequest, 1400, "id required")
		return
	}
	var row models.SocAPIKey
	if err := common.DB.First(&row, body.ID).Error; err != nil {
		fail(c, http.StatusNotFound, 1404, "no such key")
		return
	}
	now := time.Now()
	if body.Used {
		common.DB.Model(&row).UpdateColumn("last_used_at", now)
		ok(c, "ok", nil)
		return
	}
	if body.Seconds <= 0 && !body.Dead {
		fail(c, http.StatusBadRequest, 1400, "seconds or dead required")
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if len(reason) > 512 {
		reason = reason[:512]
	}
	upd := map[string]interface{}{"bench_reason": reason}
	if body.Dead {
		upd["bench_dead"] = true
	} else {
		until := now.Add(time.Duration(body.Seconds) * time.Second)
		if row.BenchUntil != nil && row.BenchUntil.After(until) {
			until = *row.BenchUntil // extend-only, across replicas
		}
		upd["bench_until"] = until
	}
	if err := common.DB.Model(&row).Updates(upd).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "persist: "+err.Error())
		return
	}
	log.Printf("soc-pool: key %d benched dead=%v seconds=%d (%s)", row.ID, body.Dead, body.Seconds, reason)
	ok(c, "ok", nil)
}
