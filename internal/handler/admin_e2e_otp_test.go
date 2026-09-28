package handler

import (
	"errors"
	"testing"
)

func TestE2EOTPAddressAllowed_DefaultPattern(t *testing.T) {
	t.Setenv("IDENTITY_E2E_OTP_EMAIL_PATTERN", "")
	cases := map[string]bool{
		"lumid-e2e-fresh-mujali6e@yao.lu": true,
		"LUMID-E2E-fresh-abc@YAO.LU":      true, // normalised like register does
		"lumid-e2e-fresh-abc@yao.lu.evil": false,
		"lumid-e2e-fresh-abc@evil.yao.lu": false,
		"someone@gmail.com":               false,
		"yao@lum.id":                      false,
		"lumid-e2e@yao.lu":                false, // bare prefix, no suffix
		"x-lumid-e2e-fresh@yao.lu":        false,
		"lumid-e2e-a@yao.lu\nx@gmail.com": false,
		"":                                false,
	}
	for in, want := range cases {
		got, err := e2eOTPAddressAllowed(in)
		if err != nil {
			t.Fatalf("%q: unexpected err %v", in, err)
		}
		if got != want {
			t.Errorf("%q: allowed=%v, want %v", in, got, want)
		}
	}
}

func TestE2EOTPAddressAllowed_Disabled(t *testing.T) {
	for _, v := range []string{"off", "OFF", "disabled", "0", "false"} {
		t.Setenv("IDENTITY_E2E_OTP_EMAIL_PATTERN", v)
		ok, err := e2eOTPAddressAllowed("lumid-e2e-fresh-x@yao.lu")
		if ok || !errors.Is(err, errE2EOTPDisabled) {
			t.Errorf("%q: want disabled, got ok=%v err=%v", v, ok, err)
		}
	}
}

func TestE2EOTPAddressAllowed_CustomPattern(t *testing.T) {
	t.Setenv("IDENTITY_E2E_OTP_EMAIL_PATTERN", `^ci-[a-z0-9]+@example\.test$`)
	if ok, _ := e2eOTPAddressAllowed("ci-abc@example.test"); !ok {
		t.Error("custom pattern should allow ci-abc@example.test")
	}
	if ok, _ := e2eOTPAddressAllowed("lumid-e2e-fresh-x@yao.lu"); ok {
		t.Error("custom pattern replaces the default, not extends it")
	}
}
