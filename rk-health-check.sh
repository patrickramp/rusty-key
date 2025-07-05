#!/bin/bash
# rk-health-check.sh

check_secret_store() {
    local base_path="/var/rusty-key"
    
    # Check directory permissions
    if [[ "$(stat -c %a "$base_path/keys")" != "700" ]]; then
        echo "ERROR: Keys directory has incorrect permissions"
        return 1
    fi
    
    # Check key files exist and have correct permissions
    if [[ ! -f "$base_path/keys/master.key" ]]; then
        echo "ERROR: Master key not found"
        return 1
    fi
    
    if [[ "$(stat -c %a "$base_path/keys/master.key")" != "600" ]]; then
        echo "ERROR: Master key has incorrect permissions"
        return 1
    fi
    
    # Test encryption/decryption
    local test_secret
    test_secret="health-check-$(date +%s)"
    local temp_file="/tmp/health-check.age"
    
    if ! rusty-key encrypt \
        --recipient "$base_path/keys/master.pub" \
        --input "$test_secret" \
        --output "$temp_file" \
        --force; then
        echo "ERROR: Encryption test failed"
        return 1
    fi
    
    local decrypted
    if ! decrypted=$(rusty-key decrypt \
        --key "$base_path/keys/master.key" \
        --input "$temp_file"); then
        echo "ERROR: Decryption test failed"
        return 1
    fi
    
    if [[ "$decrypted" != "$test_secret" ]]; then
        echo "ERROR: Encryption/decryption mismatch"
        return 1
    fi
    
    rm -f "$temp_file"
    echo "OK: Secret store healthy"
}

check_secret_store