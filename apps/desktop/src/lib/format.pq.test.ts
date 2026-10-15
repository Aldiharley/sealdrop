// Post-quantum helpers and mock parity. Runs on Node's built-in runner (`npm test` bundles
// this file with rolldown first, since Node 20 does not strip TypeScript types).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { defaultPqForReplace, kindLabel, recipientTone, recipientsText } from "./format";
import { mapSealError, selfOmittedText } from "./errors";
import { mock } from "./mock";
import { VERSION } from "./version";
import type * as T from "./types";

const PQ = "age1pq1" + "q".repeat(1990);
const X25519 = "age1qx7k4m9v2c8l5n3z6p0t7y4h2j8d5s9w3e6r1u4a7g0f2b8x5m3q9c6k4v7w2f3k2";

function sealArgs(recipients: string[]): T.SealArgs {
  return {
    input: "C:/x",
    out_dir: "C:/o",
    recipients,
    passphrase: false,
    words: "eff",
    argon2id: false,
    kdf_profile: "default",
    armor: false,
    classification: null,
    expires: null,
    allow_unrecoverable: false,
    include_self: false,
    expire_after_secs: null,
  };
}

describe("post-quantum kinds", () => {
  it("labels and tones pq like hybrid-pq", () => {
    assert.equal(kindLabel("pq"), "post-quantum");
    assert.equal(kindLabel("hybrid-pq"), "post-quantum");
    assert.equal(recipientTone("pq"), "blue");
    assert.equal(recipientsText([{ kind: "pq" }, { kind: "pq" }], false), "2 (post-quantum)");
  });

  it("leaves the other kinds unchanged", () => {
    assert.equal(kindLabel("x25519"), "x25519");
    assert.equal(kindLabel("plugin:yubikey"), "plugin");
    assert.equal(recipientTone("x25519"), "pink");
    assert.equal(recipientsText([{ kind: "x25519" }, { kind: "plugin:tpm" }], true), "2 (x25519, plugin, timed release)");
  });

  it("maps the mixing refusal to the friendly sentence", () => {
    const m = mapSealError(
      "policy refused: post-quantum recipients cannot be mixed with classical ones (classical: 0123456789abcdef); seal them separately",
    );
    assert.equal(m.text, "Post-quantum and classical recipients can't share one package. Remove one group, or seal twice.");
    assert.equal(m.field, undefined);
    // Other policy refusals keep the generic wording.
    assert.match(mapSealError("policy refused: no recipients given").text, /^sealdrop refused to seal this: no recipients given\.$/);
  });
});

describe("Keys: Replace keeps the current kind", () => {
  it("starts the switch from the current identity", () => {
    assert.equal(defaultPqForReplace("pq"), true);
    assert.equal(defaultPqForReplace("x25519"), false);
    assert.equal(defaultPqForReplace(null), false);
    assert.equal(defaultPqForReplace(undefined), false);
  });
});

describe("self-omitted note", () => {
  it("swaps the CLI hint for app wording and keeps the rest", () => {
    const core =
      "your own identity is classical (x25519), so it was not added to this post-quantum package; create a post-quantum identity with `keygen --pq` to include yourself";
    assert.equal(
      selfOmittedText(core),
      "your own identity is classical (x25519), so it was not added to this post-quantum package; turn on Post-quantum identity in Keys and create a new identity to include yourself",
    );
    const other = "your own identity is post-quantum, so it was not added to this classical package; the recipients would otherwise be mixed";
    assert.equal(selfOmittedText(other), other);
  });
});

describe("mock backend", () => {
  it("parses age1pq1 as kind pq and refuses mixing", async () => {
    const c = (await mock("parse_recipient", { s: PQ })) as T.RecipientCheck;
    assert.equal(c.kind, "pq");
    assert.equal(c.allowed, true);
    assert.equal(c.plugin, null);
    await assert.rejects(mock("seal", { req: sealArgs([PQ, X25519]) }), (e: unknown) => /cannot be mixed/.test(String(e)));
  });

  it("reports post_quantum and self_omitted on seal", async () => {
    const pq = (await mock("seal", { req: sealArgs([PQ]) })) as T.SealOut;
    assert.equal(pq.post_quantum, true);
    assert.equal(pq.self_omitted, null);
    const classical = (await mock("seal", { req: sealArgs([X25519]) })) as T.SealOut;
    assert.equal(classical.post_quantum, false);
  });

  it("leaves a classical self out of a post-quantum package, with the core's note", async () => {
    await mock("generate_identity", { force: true, pq: false });
    const out = (await mock("seal", { req: { ...sealArgs([PQ]), include_self: true } })) as T.SealOut;
    assert.equal(out.post_quantum, true);
    assert.match(out.self_omitted ?? "", /your own identity is classical \(x25519\)/);
    const same = (await mock("seal", { req: { ...sealArgs([X25519]), include_self: true } })) as T.SealOut;
    assert.equal(same.self_omitted, null);
  });

  it("generate_identity honours pq", async () => {
    const pq = (await mock("generate_identity", { force: true, pq: true })) as T.IdentityInfo;
    assert.equal(pq.kind, "pq");
    assert.equal(pq.recipient, PQ);
    const x = (await mock("generate_identity", { force: true, pq: false })) as T.IdentityInfo;
    assert.equal(x.kind, "x25519");
    assert.ok(x.recipient?.startsWith("age1q"));
  });

  it("verify and open expose post_quantum", async () => {
    const plain = (await mock("verify", { path: "C:/s/q3-findings.sealdrop.age", signer: null })) as T.VerifyOut;
    assert.equal(plain.post_quantum, false);
    const pq = (await mock("verify", { path: "C:/s/q3-findings-pq.sealdrop.age", signer: null })) as T.VerifyOut;
    assert.equal(pq.post_quantum, true);
    assert.equal(pq.recipients?.[0].kind, "pq");
    const untrusted = (await mock("verify", { path: "C:/s/q3-findings-untrusted.sealdrop.age", signer: null })) as T.VerifyOut;
    assert.equal(untrusted.ok, false);
    assert.equal(untrusted.post_quantum, null);

    const open = (args: Partial<T.OpenArgs>) =>
      mock("open_package", {
        req: { package: "C:/s/q3-findings-pq.sealdrop.age", out_dir: "C:/o", temp: false, passphrase: null, signer: null, skip_verify: false, overwrite: false, ...args },
      }) as Promise<T.OpenOut>;
    assert.equal((await open({})).post_quantum, true);
    assert.equal((await open({ skip_verify: true })).post_quantum, null);
    assert.equal((await open({ package: "C:/s/q3-findings.sealdrop.age" })).post_quantum, false);
  });
});

describe("app version", () => {
  it("VERSION matches package.json", () => {
    // `npm test` runs from apps/desktop, so package.json is in the working directory.
    const pkg = JSON.parse(readFileSync(resolve("package.json"), "utf8"));
    assert.equal(VERSION, pkg.version);
  });
});
