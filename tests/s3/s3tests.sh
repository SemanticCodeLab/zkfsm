# Runs ceph/s3-tests (MIT) cloned at test time at a pinned commit; sourced by run.sh.
# Results are reported separately and never fail the run. Excluded groups: vendor or IAM-service
# extensions, time-scaled lifecycle runs, and SSE/KMS/Select/notifications (tested elsewhere).
# With MC set, "alt" is a separate IAM user (no grants but CreateBucket), so ACL and
# bucket-policy tests see a second account; otherwise alt reuses the main credentials.
S3TESTS_REPO="${S3TESTS_REPO:-https://github.com/ceph/s3-tests.git}"
S3TESTS_COMMIT="${S3TESTS_COMMIT:-5522d1c351f75bc00ae0f64f742f3f095f5939d9}"
S3T="$HERE/.s3-tests"
# Feature markers upstream uses for things zkfsm does not implement.
S3TESTS_MARKERS="${S3TESTS_MARKERS:-not abac_test and not appendobject and not bucket_encryption and not bucket_logging and not bucket_logging_cleanup and not cloud_restore and not cloud_transition and not encryption and not fails_on_aws and not fails_without_logging_rollover and not group and not group_policy and not iam_account and not iam_cross_account and not iam_role and not iam_tenant and not iam_user and not lifecycle_expiration and not lifecycle_transition and not role_policy and not s3control and not s3select and not session_policy and not sns and not sse_s3 and not target_by_bucket and not test_of_sts and not token_claims_trust_policy_test and not token_principal_tag_role_policy_test and not token_request_tag_trust_policy_test and not token_resource_tags_test and not token_role_tags_test and not token_tag_keys_test and not user_policy and not webidentity_test}"

if [[ ! -d "$S3T/src/.git" ]]; then
  git init -q "$S3T/src" && git -C "$S3T/src" remote add origin "$S3TESTS_REPO"
fi
if [[ "$(git -C "$S3T/src" rev-parse HEAD 2>/dev/null)" != "$S3TESTS_COMMIT" ]]; then
  git -C "$S3T/src" fetch -q --depth 1 origin "$S3TESTS_COMMIT" && git -C "$S3T/src" checkout -q FETCH_HEAD
fi
if [[ ! -x "$S3T/venv/bin/python" ]]; then
  "$PY" -m venv "$S3T/venv"
  "$S3T/venv/bin/pip" install -q --no-cache-dir --disable-pip-version-check -r "$S3T/src/requirements.txt" pytest-timeout >>"$LOG" 2>&1
fi

ALT_AK="$AK" ALT_SK="$SK" ALT_ID=zkfsm
if [[ -n "${MC:-}" ]] && "$MC" --version 2>/dev/null | grep -q RELEASE; then
  export MC_CONFIG_DIR="$WORK/mcconf"
  ALT_AK=s3testsalt ALT_SK="s3tests-alt-secret-0123" ALT_ID=s3testsalt
  printf '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:CreateBucket","s3:ListAllMyBuckets"],"Resource":["arn:aws:s3:::*"]}]}' >"$WORK/alt.json"
  { "$MC" alias set zks3t "$EP" "$AK" "$SK" --api S3v4 --path on &&
    "$MC" admin user add zks3t "$ALT_AK" "$ALT_SK" &&
    "$MC" admin policy create zks3t s3tests-alt "$WORK/alt.json" &&
    "$MC" admin policy attach zks3t s3tests-alt --user "$ALT_AK"; } >>"$LOG" 2>&1 || { ALT_AK="$AK" ALT_SK="$SK" ALT_ID=zkfsm; }
fi

HOSTPORT="${EP#http://}"
cat >"$WORK/s3tests.conf" <<EOF
[DEFAULT]
host = ${HOSTPORT%:*}
port = ${HOSTPORT##*:}
is_secure = False
ssl_verify = False

[fixtures]
bucket prefix = zk-{random}-
iam name prefix = s3-tests-
iam path prefix = /s3-tests/

[s3 main]
display_name = zkfsm
user_id = zkfsm
email = main@example.com
api_name = default
access_key = $AK
secret_key = $SK

[s3 alt]
display_name = $ALT_ID
user_id = $ALT_ID
email = alt@example.com
access_key = $ALT_AK
secret_key = $ALT_SK

[s3 tenant]
display_name = zkfsm
user_id = zkfsm
access_key = $AK
secret_key = $SK
email = tenant@example.com
tenant = tenant

[iam]
email = iam@example.com
user_id = zkfsm
access_key = $AK
secret_key = $SK
display_name = zkfsm

[iam root]
access_key = $AK
secret_key = $SK
user_id = zkfsm
email = root@example.com

[iam alt root]
access_key = $AK
secret_key = $SK
user_id = zkfsm
email = altroot@example.com
EOF

S3TESTS_RESULTS="${S3TESTS_RESULTS:-$TOP/s3tests.results}"
(cd "$S3T/src" && S3TEST_CONF="$WORK/s3tests.conf" timeout "${S3TESTS_TIMEOUT:-1800}" "$S3T/venv/bin/python" -m pytest -q \
  -p no:cacheprovider --timeout=60 -o addopts= --junitxml="$WORK/s3tests.xml" -m "$S3TESTS_MARKERS" \
  s3tests/functional/test_s3.py s3tests/functional/test_headers.py >>"$LOG" 2>&1) || true
if [[ -f "$WORK/s3tests.xml" ]]; then
  "$S3T/venv/bin/python" "$HERE/junit_results.py" "$WORK/s3tests.xml" "$SUITE" "$S3TESTS_RESULTS" >/dev/null
  grep $'^FAIL\t' "$S3TESTS_RESULTS" | cut -f2 | sed 's/^/s3-tests fail: /' >>"$LOG"
else
  echo "s3-tests produced no results; see $LOG"
fi
