package handler

import "testing"

// "install the <name> app" is how anybody actually asks for an install, and it
// was the one shape the router could not hear.
//
// controlIntentPhrases carries the literals "install the app" and "install
// app", matched with strings.Contains. Both are exact substrings, so the
// moment a name sits between the article and the noun — which it does in every
// real request, because an install has to say WHAT to install — the substring
// is gone and the turn stays on claude-code, whose CLI toolset cannot see
// install_app at all. The user gets "I don't have a tool for that" for the
// single most obvious control-plane verb in the product.
func TestControlIntentRecognisesInstallNamedApp(t *testing.T) {
	yes := []string{
		// name between the verb and the noun — the reported shape
		"install the quant-research app",
		"install the mbb-ai app",
		"please install the vla-curation app for me",
		"install the findata app",
		// no article
		"install quant-research app",
		// name AFTER the noun
		"install the app quant-research",
		"install app mbb-ai",
		// neighbouring verbs for the same action
		"add the quant-research app",
		"get the mbb-ai app",
		"set up the findata app to my tenant",
		"reinstall the quant-research app",
		// underscored slug, and a capitalised one
		"install the case_cycle app",
		"install the Quant-Research app",
		// NO name — the app is implied by the conversation. This is what the
		// removed literals used to serve, and dropping it was a regression the
		// suite would not have caught, because nothing asserted it.
		"install the app",
		"install the app now",
		"install the app please",
		"uninstall the app",
		"remove the app",
		"reinstall the app.",
	}
	for _, m := range yes {
		if !controlIntent(userMsg(m)) {
			t.Errorf("named-app install not routed to a tool-capable provider: %q", m)
		}
	}
}

// The bar every pattern in this router has to clear: a super_admin doing
// ordinary code and shell work must still reach claude-code. "install" is a
// developer's most-typed verb, so anchoring on it is exactly where a pattern
// goes wrong — "app" is an ordinary English word and the head noun of several
// framework idioms.
func TestControlIntentLeavesInstallCodeTurnsAlone(t *testing.T) {
	no := []string{
		// no platform noun at all
		"install numpy",
		"install the dependencies",
		"pip install -r requirements.txt",
		"npm install in the app directory",
		// "app" present but NOT the object being installed
		"install the app dependencies",
		"install the app router in next.js",
		"how do I install the app's node modules?",
		// framework/stack senses of "<x> app"
		"install the react app",
		"install the node app",
		"set up the flask app locally",
		"how do I install the web app on the emulator?",
		"install the django app into INSTALLED_APPS",
		// talking about installing, not asking for it
		"what does install_app actually do under the hood?",
		"where is the install the app button rendered?",
	}
	for _, m := range no {
		if controlIntent(userMsg(m)) {
			t.Errorf("code/shell turn stolen from claude-code: %q", m)
		}
	}
}
