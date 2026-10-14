import copy
import json
import unittest

from runtime.dns import assemble_dns, dns_limitations, DOMESTIC, REMOTE


def fixture():
    providers = {name: {"type": "inline", "behavior": "domain", "payload": ["+.example.test"]}
                 for name in ("private-domain", "services-proxy", "cn-domain", "personal-direct-domain", "personal-proxy-domain")}
    document = {"rule-providers": providers, "rules": ["MATCH,节点选择"],
                "tun": {"enable": False, "stack": "mixed"},
                "dns": {"listen": "127.0.0.1:5335", "enhanced-mode": "fake-ip"}}
    manifest = {"schema_version": 2, "policy_version": "balanced-v2"}
    inline = {"schema_version": 2, "sections": {n: [] for n in ("personal_direct", "personal_proxy", "private", "services", "direct")},
              "domain_index": {name: list(provider["payload"]) for name, provider in providers.items()}}
    return document, manifest, inline


class DNSV2Tests(unittest.TestCase):
    def test_v1_is_exact_noop_even_with_invalid_dns_override(self):
        document = {"dns": None}
        self.assertIs(assemble_dns(document, {"schema_version": 1}, {}, override="bad"), document)

    def test_order_and_resolvers_are_rebuilt_after_sorted_state_roundtrip(self):
        document, manifest, inline = fixture()
        result = assemble_dns(document, manifest, inline)
        expected = list(result["dns"]["nameserver-policy"].items())
        reloaded = json.loads(json.dumps(result, sort_keys=True))
        rebuilt = assemble_dns(reloaded, manifest, inline)
        self.assertEqual(list(rebuilt["dns"]["nameserver-policy"].items()), expected)
        self.assertEqual(rebuilt["dns"]["direct-nameserver"], REMOTE)
        self.assertEqual(rebuilt["dns"]["proxy-server-nameserver"], DOMESTIC)
        keys = list(rebuilt["dns"]["nameserver-policy"])
        self.assertLess(keys.index("rule-set:personal-direct-domain"), keys.index("+.lan"))
        self.assertLess(keys.index("rule-set:services-proxy"), keys.index("rule-set:cn-domain"))

    def test_inputs_unchanged_and_unrelated_settings_preserved(self):
        document, manifest, inline = fixture()
        original = copy.deepcopy(document)
        result = assemble_dns(document, manifest, inline)
        self.assertEqual(document, original)
        for key in ("tun", "rules"):
            self.assertEqual(result[key], original[key])
        self.assertEqual(result["dns"]["listen"], original["dns"]["listen"])

    def test_migrates_only_known_legacy_policies_and_removes_fallback(self):
        document, manifest, inline = fixture()
        document["dns"].update({"fallback": ["223.5.5.5"], "fallback-filter": {"geoip": True},
            "nameserver-policy": {"rule-set:private": "system", "rule-set:direct": DOMESTIC,
                                  "rule-set:apple": [x.split("#")[0] for x in DOMESTIC], "rule-set:icloud": DOMESTIC},
            "proxy-server-nameserver-policy": {"node.example": DOMESTIC}})
        result = assemble_dns(document, manifest, inline)
        self.assertNotIn("fallback", result["dns"])
        self.assertNotIn("fallback-filter", result["dns"])
        self.assertNotIn("rule-set:apple", result["dns"]["nameserver-policy"])
        self.assertNotIn("proxy-server-nameserver-policy", result["dns"])

    def test_domain_predicates_project_but_connection_predicates_only_report(self):
        document, manifest, inline = fixture()
        inline["sections"]["personal_proxy"] = ["DOMAIN-REGEX,^api[0-9]+\\.example\\.test$", "PROCESS-NAME,example.exe", "DST-PORT,443"]
        inline["sections"]["direct"] = ["DOMAIN-KEYWORD,domestic"]
        result = assemble_dns(document, manifest, inline)
        self.assertEqual(result["rule-providers"]["dns-only-personal"]["payload"], inline["sections"]["personal_proxy"][:1])
        self.assertEqual(result["dns"]["nameserver-policy"]["rule-set:dns-only-direct"], DOMESTIC)
        self.assertEqual(len(dns_limitations(inline)), 2)
        self.assertNotIn("dns-only-private", result["rule-providers"])

    def test_optional_providers_are_not_referenced_when_absent(self):
        document, manifest, inline = fixture()
        del document["rule-providers"]["personal-direct-domain"]
        result = assemble_dns(document, manifest, inline)
        self.assertNotIn("rule-set:personal-direct-domain", result["dns"]["nameserver-policy"])

    def test_optional_generated_policy_is_removed_when_next_snapshot_drops_provider(self):
        document, manifest, inline = fixture()
        inline["sections"]["personal_proxy"] = ["DOMAIN-KEYWORD,old-personal"]
        document = assemble_dns(document, manifest, inline)
        del document["rule-providers"]["personal-direct-domain"]
        inline["sections"]["personal_proxy"] = []
        result = assemble_dns(document, manifest, inline)
        self.assertNotIn("rule-set:personal-direct-domain", result["dns"]["nameserver-policy"])
        self.assertNotIn("rule-set:dns-only-personal", result["dns"]["nameserver-policy"])

    def test_nonconflicting_proxy_encrypted_custom_policy_survives(self):
        document, manifest, inline = fixture()
        custom = {"dns": {"nameserver-policy": {"+.custom.test": "https://dns.quad9.net/dns-query#节点选择"}}}
        result = assemble_dns(document, manifest, inline, override=custom)
        self.assertEqual(result["dns"]["nameserver-policy"]["+.custom.test"], custom["dns"]["nameserver-policy"]["+.custom.test"])
        self.assertEqual(assemble_dns(result, manifest, inline, override=custom), result)
        self.assertEqual(assemble_dns(result, manifest, inline), result)

    def test_unsafe_or_unprovable_overrides_reject_without_mutation(self):
        for key, value in (("+.example.test", "223.5.5.5"), ("+.example.test", DOMESTIC),
                           ("+.example.test", "https://dns.google/dns-query"),
                           ("+.example.test", "system"), ("rule-set:missing", REMOTE),
                           ("geosite:cn", REMOTE), ("rule-set:apple", ["https://9.9.9.9/dns-query#DIRECT"]),
                           ("rule-set:cn-domain", REMOTE), ("child.localhost", REMOTE),
                           ("+.example.test", "")):
            document, manifest, inline = fixture()
            before = copy.deepcopy(document)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                assemble_dns(document, manifest, inline, {"dns": {"nameserver-policy": {key: value}}})
            self.assertEqual(document, before)

    def test_node_bootstrap_cannot_depend_on_proxy(self):
        document, manifest, inline = fixture()
        with self.assertRaises(ValueError):
            assemble_dns(document, manifest, inline, {"dns": {"proxy-server-nameserver-policy": {"node.test": REMOTE}}})

    def test_encrypted_proxy_custom_still_rejects_managed_domain_overlap(self):
        document, manifest, inline = fixture()
        inline["domain_index"].update({"cn-domain": ["+.cn.example.com"],
                                      "private-domain": ["nas.private.test"],
                                      "personal-direct-domain": ["wallet.personal.test"],
                                      "personal-proxy-domain": ["+.proxy.personal.test"],
                                      "services-proxy": ["api.service.test"]})
        for key in ("nas.lan", "+.com", "cn.example.com", "sub.cn.example.com",
                    "nas.private.test", "wallet.personal.test", "+.personal.test",
                    "sub.proxy.personal.test", "api.service.test", "+.service.test"):
            before = copy.deepcopy(document)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "overlaps managed domains"):
                assemble_dns(document, manifest, inline, {"nameserver-policy": {key: REMOTE}})
            self.assertEqual(document, before)

    def test_domain_index_exact_rule_does_not_cover_its_children(self):
        document, manifest, inline = fixture()
        inline["domain_index"] = {name: ["exact.example.test"] for name in inline["domain_index"]}
        result = assemble_dns(document, manifest, inline, {"nameserver-policy": {"child.exact.example.test": REMOTE}})
        self.assertIn("child.exact.example.test", result["dns"]["nameserver-policy"])

    def test_custom_policy_requires_complete_domain_index(self):
        for mutation in (lambda value: value.pop("domain_index"),
                         lambda value: value["domain_index"].pop("services-proxy")):
            document, manifest, inline = fixture()
            mutation(inline)
            with self.assertRaisesRegex(ValueError, "complete snapshot domain_index"):
                assemble_dns(document, manifest, inline, {"nameserver-policy": {"safe.other.test": REMOTE}})
            # Known generated/default migration needs no custom-policy proof.
            assemble_dns(document, manifest, inline)

    def test_custom_exact_domain_checks_regex_and_keyword_predicates(self):
        document, manifest, inline = fixture()
        inline["sections"]["services"] = [r"DOMAIN-REGEX,^API[0-9]+\.OUTSIDE\.TEST$", "DOMAIN-KEYWORD,SPECIAL-APP"]
        result = assemble_dns(document, manifest, inline, {"nameserver-policy": {"safe.other.test": REMOTE}})
        self.assertIn("safe.other.test", result["dns"]["nameserver-policy"])
        for key in ("api123.outside.test", "special-app.other.test", "+.safe.other.test"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                assemble_dns(document, manifest, inline, {"nameserver-policy": {key: REMOTE}})

    def test_unprovable_regex_or_policy_syntax_is_rejected(self):
        for regex in (r"^[[:digit:]]+\.outside\.test$", r"\p{L}+\.outside\.test$", r"[a-z-[aeiou]]", "("):
            document, manifest, inline = fixture()
            inline["sections"]["private"] = ["DOMAIN-REGEX," + regex]
            with self.subTest(regex=regex), self.assertRaises(ValueError):
                assemble_dns(document, manifest, inline, {"nameserver-policy": {"safe.other.test": REMOTE}})
        for key in ("*.safe.other.test", ".safe.other.test", "rule-set:services-proxy", "geosite:cn"):
            document, manifest, inline = fixture()
            with self.subTest(key=key), self.assertRaises(ValueError):
                assemble_dns(document, manifest, inline, {"nameserver-policy": {key: DOMESTIC if key.startswith("rule-set:") else REMOTE}})


if __name__ == "__main__":
    unittest.main()
