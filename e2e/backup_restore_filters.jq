def tenant_record_jwks:
  .served_snapshot
  | [
      (
        .ec.published[]
        | .public_jwk + {
            kty: "EC",
            alg: "ES256",
            use: "sig",
            crv: "P-256"
          }
      ),
      (
        .rsa.published[]
        | .public_jwk + {
            kty: "RSA",
            alg: "RS256",
            use: "sig"
          }
      )
    ]
  | sort_by(.kid);

def tenant_record_key_arns:
  .served_snapshot
  | [.ec.published[].key_arn, .rsa.published[].key_arn]
  | .[];

def tenant_record_signing_keys:
  .served_snapshot
  | [
      (
        .ec.published[]
        | {
            key_arn,
            public_jwk: (
              .public_jwk + {
                kty: "EC",
                crv: "P-256"
              }
            ),
            signing_algorithm: "ECDSA_SHA_256"
          }
      ),
      (
        .rsa.published[]
        | {
            key_arn,
            public_jwk: (
              .public_jwk + {
                kty: "RSA"
              }
            ),
            signing_algorithm: "RSASSA_PKCS1_V1_5_SHA_256"
          }
      )
    ]
  | sort_by(.key_arn, .signing_algorithm, .public_jwk.kid);

def canonical_configuration_items($kind):
  .Items
  | if $kind == "clients" then sort_by(.client_id.S)
    elif $kind == "workload_trust" then sort_by(.binding_id.S)
    elif $kind == "federation" then sort_by(.tenant_id.S, .upstream_idp_id.S)
    elif $kind == "scim_groups" then sort_by(.pk.S, .sk.S)
    elif $kind == "domain_map" then sort_by(.domain.S)
    else error("unknown configuration snapshot kind: \($kind)")
    end;

def canonical_identity_items($kind):
  .Items
  | if $kind == "users" then sort_by(.user_id.S)
    elif $kind == "passkeys" then sort_by(.credential_id.S)
    elif $kind == "password_credentials" then sort_by(.user_id.S)
    else error("unknown identity snapshot kind: \($kind)")
    end;

def tenant_prefixes($id; $tenants):
  [
    $tenants[]
    | (. + "\u001f") as $prefix
    | select($id | startswith($prefix))
    | $prefix
  ];

def nonnegative_integer:
  type == "number" and . >= 0 and floor == .;

def dynamo_nonnegative_integer_value:
  (.N? // null) as $raw
  | if ($raw | type) != "string" then null
    else try ($raw | tonumber) catch null
    end
  | if . != null and nonnegative_integer then . else null end;

def canonical_user_ids_are_valid($users; $tenants):
  all(
    $users[]
    | select(.record_type == null);
    (.user_id.S? // "") as $user_id
    | tenant_prefixes($user_id; $tenants) as $prefixes
    | ($prefixes | length) == 1 and
      ($user_id | length) > ($prefixes[0] | length) and
      ((.created_at | dynamo_nonnegative_integer_value) != null)
  );

def credential_tenant_ownership_is_valid($users; $kind; $tenants):
  [
    $users[]
    | select(.record_type == null)
    | .user_id.S
  ] as $canonical_ids
  | canonical_user_ids_are_valid($users; $tenants) and
    all(
        .[];
        . as $item
        | ($item.user_id.S? // "") as $user_id
        | tenant_prefixes($user_id; $tenants) as $user_prefixes
        | if ($user_prefixes | length) != 1 then false
          else
            $user_prefixes[0] as $prefix
            | ($canonical_ids | index($user_id)) != null and
              (
                if $kind == "password_credentials" then true
                elif $kind == "passkeys" then
                  tenant_prefixes(
                    ($item.credential_id.S? // "");
                    $tenants
                  ) == [$prefix]
                else error("unknown credential ownership kind: \($kind)")
                end
              )
          end
      );

def logical_grant_projection($item; $tenants):
  (try ($item.grant_json.S | fromjson) catch null) as $grant
  | if ($grant | type) != "object" then null
    else
      tenant_prefixes(($item.grant_id.S? // ""); $tenants) as $prefixes
      | ($grant.effective_pv // 0) as $effective_pv
      | ($grant.revision // 0) as $revision
      | ($grant.credential_epoch // 0) as $credential_epoch
      | if
          ($prefixes | length) == 1 and
          ($grant.grant_id | type == "string" and length > 0) and
          ($grant.user_id | type == "string" and length > 0) and
          ($effective_pv | nonnegative_integer) and
          ($revision | nonnegative_integer) and
          ($credential_epoch | nonnegative_integer)
        then {
          prefix: $prefixes[0],
          grant: $grant,
          effective_pv: $effective_pv,
          revision: $revision,
          credential_epoch: $credential_epoch
        }
        else null
        end
    end;

def optional_grant_projection_values_are_valid($item; $projection):
  (
    ($item.revision == null) or
    (($item.revision | dynamo_nonnegative_integer_value) ==
      $projection.revision)
  ) and
  (
    ($item.credential_epoch == null) or
    (($item.credential_epoch | dynamo_nonnegative_integer_value) ==
      $projection.credential_epoch)
  );

def grant_item_is_valid($tenants; $allow_legacy_projection):
  . as $item
  | logical_grant_projection($item; $tenants) as $projection
  | if $projection == null then false
    else
      ($item.gv_tenant.S? // null) as $gv_tenant
      | ($item.effective_pv.N? // null) as $physical_effective_pv
      | ($item.gv_tenant == null and $item.effective_pv == null) as $legacy
      | ($gv_tenant != null and $physical_effective_pv != null) as $projected
      | $item.grant_id.S ==
          ($projection.prefix + $projection.grant.grant_id) and
        $item.user_id.S ==
          ($projection.prefix + $projection.grant.user_id) and
        ($item.policy_version == null) and
        ($item.policy_text == null) and
        ($item.policy_digest == null) and
        (
          (
            $projected and
            $gv_tenant == ($projection.prefix + "gv") and
            (($item.effective_pv | dynamo_nonnegative_integer_value) ==
              $projection.effective_pv)
          ) or
          ($allow_legacy_projection and $legacy)
        ) and
        optional_grant_projection_values_are_valid($item; $projection)
    end;

def policy_version_item_is_valid($tenants):
  . as $item
  | tenant_prefixes(($item.grant_id.S? // ""); $tenants) as $prefixes
  | ($prefixes | length) == 1 and
    $item.grant_id.S == ($prefixes[0] + "policy-version") and
    (($item.policy_version | dynamo_nonnegative_integer_value) != null) and
    ($item.user_id == null) and
    ($item.gv_tenant == null) and
    ($item.effective_pv == null) and
    ($item.revision == null) and
    ($item.credential_epoch == null) and
    ($item.grant_json == null) and
    ($item.policy_text == null) and
    ($item.policy_digest == null);

def policy_artifact_item_is_valid($tenants):
  . as $item
  | tenant_prefixes(($item.grant_id.S? // ""); $tenants) as $prefixes
  | if ($prefixes | length) != 1 then false
    else
      ($item.grant_id.S | ltrimstr($prefixes[0])) as $logical_id
      | ($logical_id | test("^policy-artifact#[1-9][0-9]*$")) and
        (($item.policy_text.S? // "") | length > 0) and
        (($item.policy_digest.S? // "") | test("^[0-9a-f]{64}$")) and
        ($item.policy_version == null) and
        ($item.user_id == null) and
        ($item.gv_tenant == null) and
        ($item.effective_pv == null) and
        ($item.revision == null) and
        ($item.credential_epoch == null) and
        ($item.grant_json == null)
    end;

def grant_table_item_is_valid($tenants; $allow_legacy_projection):
  if .grant_json.S? != null then
    grant_item_is_valid($tenants; $allow_legacy_projection)
  elif policy_version_item_is_valid($tenants) then true
  elif policy_artifact_item_is_valid($tenants) then true
  else false
  end;

def grant_projection_migration_candidates($tenants):
  if all(.Items[]; grant_table_item_is_valid($tenants; true)) then
    [
      .Items[]
      | select(.grant_json.S? != null)
      | . as $item
      | logical_grant_projection($item; $tenants) as $projection
      | select(
          $item.gv_tenant == null and
          $item.effective_pv == null
        )
      | {
          grant_id: $item.grant_id.S,
          user_id: $item.user_id.S,
          gv_tenant: ($projection.prefix + "gv"),
          effective_pv: ($projection.effective_pv | tostring),
          revision: ($item.revision.N? // null),
          grant_json: $item.grant_json.S
        }
    ]
    | sort_by(.grant_id)
  else
    error("Grant table has an unknown row or an invalid projection")
  end;

def canonical_grant_items($tenants):
  if all(.Items[]; grant_table_item_is_valid($tenants; false)) then
    .Items | sort_by(.grant_id.S)
  else
    error("Grant authority has an unknown row or invalid physical/logical projection")
  end;

def user_tenant_ownership_is_valid($tenants):
  . as $items
  | [
      $items[]
      | select(.record_type == null)
      | .user_id.S
    ] as $canonical_ids
  | canonical_user_ids_are_valid($items; $tenants) and
    all(
        $items[];
        . as $item
        | ($item.user_id.S? // "") as $id
        | tenant_prefixes($id; $tenants) as $prefixes
        | if ($prefixes | length) != 1 then false
          else
            $prefixes[0] as $prefix
            | if $item.record_type == null then
                ($item.canonical_user_id == null) and
                (
                  $item.scim_tenant == null or
                  $item.scim_tenant.S == ($prefix + "scim-users")
                ) and
                (
                  $item.email == null or
                  ($item.email.S? // "" | startswith($prefix))
                )
              elif $item.record_type.S == "scim_alias" then
                (
                  $item.alias_kind.S == "external" or
                  $item.alias_kind.S == "username"
                ) and
                (($item.alias_value.S? // "") | length > 0) and
                (($item.canonical_user_id.S? // "") | startswith($prefix)) and
                ($canonical_ids | index($item.canonical_user_id.S)) != null
              elif $item.record_type.S == "scim_create" then
                (
                  ($id | ltrimstr($prefix)) |
                  test("^scim-create:[A-Za-z0-9_-]{43}$")
                ) and
                (($item.canonical_user_id.S? // "") | startswith($prefix)) and
                ($canonical_ids | index($item.canonical_user_id.S)) != null
              else false
              end
          end
      );
