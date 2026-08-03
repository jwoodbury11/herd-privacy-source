import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

const infrastructure = resolve(
  import.meta.dirname,
  "../../infrastructure/gcp-confidential-space",
);

async function source(name) {
  return readFile(resolve(infrastructure, name), "utf8");
}

async function allTerraformSource() {
  const names = (await readdir(infrastructure))
    .filter((name) => name.endsWith(".tf"))
    .sort();
  return Promise.all(names.map((name) => source(name))).then((files) =>
    files.join("\n"),
  );
}

test("Terraform makes the custodian database durable and non-administrable by the workload", async () => {
  const [foundation, identity, compute, variables] = await Promise.all([
    source("foundation.tf"),
    source("identity.tf"),
    source("compute.tf"),
    source("variables.tf"),
  ]);
  assert.match(foundation, /resource "google_firestore_database" "transparency"/u);
  assert.match(
    foundation,
    /delete_protection_state\s*=\s*"DELETE_PROTECTION_ENABLED"/u,
  );
  assert.match(
    foundation,
    /point_in_time_recovery_enablement\s*=\s*"POINT_IN_TIME_RECOVERY_ENABLED"/u,
  );
  assert.match(foundation, /resource "google_project_iam_custom_role" "transparency_appender"/u);
  const grantedPermissions = [...foundation.matchAll(/"(datastore\.[a-zA-Z.]+)"/gu)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(grantedPermissions, [
    "datastore.databases.get",
    "datastore.entities.create",
    "datastore.entities.get",
    "datastore.entities.update",
  ]);
  assert.doesNotMatch(foundation, /"datastore\.entities\.delete"/u);
  assert.doesNotMatch(foundation, /"datastore\.entities\.list"/u);
  assert.doesNotMatch(identity, /roles\/datastore\.(?:user|admin|owner|editor)/u);
  assert.match(
    identity,
    /principalSet:\/\/iam\.googleapis\.com\/projects\/\$\{var\.key_project_number\}\/locations\/global\/workloadIdentityPools\/\$\{local\.workload_identity_pool_id\}\/attribute\.image_digest\/\$\{local\.effective_image_digest\}/u,
  );
  assert.match(
    identity,
    /role\s*=\s*google_project_iam_custom_role\.transparency_appender\.name/u,
  );
  assert.ok(
    identity.includes(
      'expression  = "resource.name == \\"projects/${var.key_project_id}/databases/${var.transparency_database_id}\\""',
    ),
  );
  assert.match(identity, /assertion\.oemid\s*==\s*11129/u);
  assert.match(identity, /size\(assertion\.attester_tcb\)\s*==\s*1/u);
  assert.match(identity, /assertion\.attester_tcb\[0\]\s*==\s*"INTEL"/u);
  assert.match(identity, /size\(assertion\.swversion\)\s*==\s*1/u);
  assert.match(identity, /jsonencode\(var\.confidential_space_swversions\)/u);
  assert.match(variables, /regex\("\^\[0-9\]\{6\}\$", version\)/u);
  assert.match(identity, /size\(assertion\.google_service_accounts\)\s*==\s*1/u);
  assert.match(
    identity,
    /assertion\.google_service_accounts\[0\]\s*==\s*"\$\{google_service_account\.workload\.email\}"/u,
  );
  assert.match(
    identity,
    /size\(assertion\.submods\.confidential_space\.monitoring_enabled\)\s*==\s*1/u,
  );
  assert.match(compute, /request_path\s*=\s*"\/readyz"/u);
});

test("Terraform independently wraps the global log identity and grants only the exact attested digest", async () => {
  const [foundation, identity, outputs] = await Promise.all([
    source("foundation.tf"),
    source("identity.tf"),
    source("outputs.tf"),
  ]);
  assert.match(
    foundation,
    /resource "google_kms_crypto_key" "transparency_identity"/u,
  );
  assert.match(
    foundation,
    /name\s*=\s*"response-transparency-identity"/u,
  );
  assert.deepEqual(
    [...foundation.matchAll(/rotation_period\s*=\s*"7776000s"/gu)].length,
    2,
  );
  assert.match(
    identity,
    /resource "google_kms_crypto_key_iam_member" "attested_transparency_identity_decrypter"/u,
  );
  assert.match(
    identity,
    /crypto_key_id\s*=\s*google_kms_crypto_key\.transparency_identity\.id/u,
  );
  assert.equal(
    [
      ...identity.matchAll(
        /role\s*=\s*"roles\/cloudkms\.cryptoKeyDecrypter"/gu,
      ),
    ].length,
    2,
  );
  assert.equal(
    [
      ...identity.matchAll(
        /attribute\.image_digest\/\$\{local\.effective_image_digest\}/gu,
      ),
    ].length,
    3,
  );
  assert.doesNotMatch(identity, /create_before_destroy/u);
  assert.match(outputs, /output "transparency_kms_key_resource"/u);
});

test("Terraform permits only restricted Google API egress without NAT or a default route", async () => {
  const [foundation, egress, compute, locals, allInfrastructure] = await Promise.all([
    source("foundation.tf"),
    source("restricted-egress.tf"),
    source("compute.tf"),
    source("locals.tf"),
    allTerraformSource(),
  ]);

  assert.match(foundation, /delete_default_routes_on_create\s*=\s*true/u);
  assert.match(foundation, /private_ip_google_access\s*=\s*true/u);
  assert.match(compute, /stack_type\s*=\s*"IPV4_ONLY"/u);
  assert.match(locals, /"dns\.googleapis\.com"/u);
  assert.doesNotMatch(allInfrastructure, /resource "google_compute_router(?:_nat)?"/u);
  assert.doesNotMatch(compute, /access_config\s*\{/u);

  assert.deepEqual(
    [...egress.matchAll(/dest_range\s*=\s*"([^"]+)"/gu)].map(
      (match) => match[1],
    ).sort(),
    ["199.36.153.4/30"],
  );
  assert.equal(
    [...egress.matchAll(/next_hop_gateway\s*=\s*"default-internet-gateway"/gu)]
      .length,
    1,
  );
  assert.equal(
    [...egress.matchAll(/^\s{2}tags\s*=\s*\["\$\{var\.name_prefix\}-backend"\]/gmu)]
      .length,
    1,
  );
  assert.doesNotMatch(egress, /dest_range\s*=\s*"0\.0\.0\.0\/0"/u);

  assert.deepEqual(
    [...egress.matchAll(/destination_ranges\s*=\s*\["([^"]+)"\]/gu)]
      .map((match) => match[1])
      .sort(),
    ["0.0.0.0/0", "199.36.153.4/30"],
  );
  assert.equal(
    [...egress.matchAll(/priority\s*=\s*900/gu)].length,
    1,
  );
  assert.equal(
    [...egress.matchAll(/ports\s*=\s*\["443"\]/gu)].length,
    1,
  );
  assert.match(
    egress,
    /resource "google_compute_firewall" "evaluator_deny_other_egress"[\s\S]*?priority\s*=\s*1000[\s\S]*?destination_ranges\s*=\s*\["0\.0\.0\.0\/0"\][\s\S]*?deny\s*\{\s*protocol\s*=\s*"all"/u,
  );

  for (const address of ["4", "5", "6", "7"]) {
    assert.equal(
      [...egress.matchAll(new RegExp(`"199\\.36\\.153\\.${address}"`, "gu"))]
        .length,
      2,
    );
  }
  assert.match(
    egress,
    /name\s*=\s*"\*\.googleapis\.com\."[\s\S]*?rrdatas\s*=\s*\["restricted\.googleapis\.com\."\]/u,
  );
  assert.match(
    egress,
    /name\s*=\s*"\*\.pkg\.dev\."[\s\S]*?rrdatas\s*=\s*\["pkg\.dev\."\]/u,
  );

  assert.match(
    egress,
    /resource "google_dns_response_policy" "evaluator_egress"[\s\S]*?network_url\s*=\s*google_compute_network\.evaluator\.id/u,
  );
  assert.equal(
    [...egress.matchAll(/provider\s*=\s*google-beta\.workload/gu)].length,
    4,
  );
  for (const dnsName of [
    "googleapis.com.",
    "*.googleapis.com.",
    "pkg.dev.",
    "*.pkg.dev.",
  ]) {
    const escapedName = dnsName.replaceAll(".", "\\.").replaceAll("*", "\\*");
    assert.match(
      egress,
      new RegExp(
        `dns_name\\s*=\\s*"${escapedName}"[\\s\\S]*?behavior\\s*=\\s*"bypassResponsePolicy"`,
        "u",
      ),
    );
  }
  assert.match(
    egress,
    /resource "google_dns_response_policy_rule" "deny_other_names"[\s\S]*?dns_name\s*=\s*"\*\."[\s\S]*?name\s*=\s*"\*\."[\s\S]*?type\s*=\s*"A"[\s\S]*?rrdatas\s*=\s*\["0\.0\.0\.0"\]/u,
  );
});

test("Terraform applies a dedicated edge throttle to public nonce attestation and keeps edge logs off", async () => {
  const loadBalancer = await source("load-balancer.tf");
  assert.match(
    loadBalancer,
    /rule\s*\{[\s\S]*?priority\s*=\s*900[\s\S]*?request\.path == '\/api\/v1\/attestation'[\s\S]*?count\s*=\s*60[\s\S]*?interval_sec\s*=\s*60[\s\S]*?enforce_on_key\s*=\s*"IP"/u,
  );
  assert.match(
    loadBalancer,
    /resource "google_compute_backend_service" "evaluator"[\s\S]*?log_config\s*\{\s*enable\s*=\s*false/u,
  );
});
