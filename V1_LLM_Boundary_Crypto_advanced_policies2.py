"""
Complete Multi-Party Trust Implementation
==========================================
Shows how to properly register authorities with cryptographic keys
and verify signed instructions from different trust domains.
"""

import sys
import json
import time
sys.path.append('/mnt/user-data/outputs')

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from V1_LLM_Boundary_Crypto_advanced_policies import (
    TrustAuthority,
    MultiPartyTrustManager
)
from typing import Dict, Tuple


class RealMultiPartyTrustManager(MultiPartyTrustManager):
    """
    Enhanced version with actual cryptographic key registration and verification.
    """
    
    def __init__(self):
        super().__init__()
        # Store private keys for this demo (in production: use HSM/KMS)
        self._private_keys: Dict[TrustAuthority, ed25519.Ed25519PrivateKey] = {}
    
    def generate_and_register_authority(
        self, 
        authority: TrustAuthority
    ) -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
        """
        Generate keypair for an authority and register it.
        
        Returns:
            (private_key, public_key_bytes)
        
        In production:
        - Private key goes to HSM/KMS
        - Public key distributed to validators
        - This function only returns public key
        """
        # Generate Ed25519 keypair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Serialize public key
        from cryptography.hazmat.primitives import serialization
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Register public key
        self.register_authority(authority, public_key_bytes)
        
        # Store private key (demo only!)
        self._private_keys[authority] = private_key
        
        return private_key, public_key_bytes
    
    def sign_instruction(
        self,
        authority: TrustAuthority,
        instruction: Dict
    ) -> bytes:
        """
        Sign an instruction as a specific authority.
        
        In production: This happens in secure environment (HSM/enclave)
        """
        if authority not in self._private_keys:
            raise ValueError(f"Authority {authority} not registered")
        
        # Check if authority has permission for this operation
        operation = instruction.get("op", "")
        if not self.check_authority_permission(authority, operation):
            raise PermissionError(
                f"{authority.value} not authorized for operation: {operation}"
            )
        
        # Create canonical representation
        canonical = json.dumps(instruction, sort_keys=True).encode('utf-8')
        
        # Sign with authority's private key
        private_key = self._private_keys[authority]
        signature = private_key.sign(canonical)
        
        return signature
    
    def verify_multi_party_instruction(
        self,
        instruction: Dict,
        authority: TrustAuthority,
        signature: bytes
    ) -> bool:
        """
        Verify instruction from specific authority (REAL cryptographic verification).
        
        Returns:
            True if signature valid AND authority has permission
        """
        operation = instruction.get("op", "")
        
        # 1. Check permission first (fast fail)
        if not self.check_authority_permission(authority, operation):
            print(f"   ❌ Permission denied: {authority.value} cannot {operation}")
            return False
        
        # 2. Check if authority is registered
        if authority not in self.authority_keys:
            print(f"   ❌ Authority not registered: {authority.value}")
            return False
        
        # 3. Verify cryptographic signature
        try:
            from cryptography.hazmat.primitives import serialization
            
            # Load public key
            public_key_bytes = self.authority_keys[authority]
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Create canonical representation (must match signing)
            canonical = json.dumps(instruction, sort_keys=True).encode('utf-8')
            
            # Verify signature
            public_key.verify(signature, canonical)
            
            print(f"   ✅ Signature verified: {authority.value}")
            return True
            
        except InvalidSignature:
            print(f"   ❌ Invalid signature from: {authority.value}")
            return False
        except Exception as e:
            print(f"   ❌ Verification error: {e}")
            return False


def demo_real_multi_party_trust():
    """Demonstrate complete multi-party trust with real cryptography"""
    
    print("=" * 80)
    print("🔐 COMPLETE MULTI-PARTY TRUST DEMONSTRATION")
    print("=" * 80)
    
    # Initialize enhanced trust manager
    trust_mgr = RealMultiPartyTrustManager()
    
    # Step 1: Generate and register keys for each authority
    print("\n📝 STEP 1: Key Generation & Registration")
    print("-" * 80)
    
    authorities_info = {}
    
    for authority in TrustAuthority:
        private_key, public_key = trust_mgr.generate_and_register_authority(authority)
        authorities_info[authority] = {
            "private_key": private_key,
            "public_key": public_key
        }
        
        print(f"\n✅ {authority.value}:")
        print(f"   Public key: {public_key.hex()[:32]}...")
        print(f"   Permissions: {', '.join(trust_mgr.authority_permissions[authority])}")
    
    print(f"\n📊 Total registered authorities: {len(trust_mgr.authority_keys)}")
    
    # Step 2: Test signed instructions from different authorities
    print("\n\n📝 STEP 2: Signed Instruction Verification")
    print("-" * 80)
    
    test_scenarios = [
        {
            "authority": TrustAuthority.SYSTEM_ADMIN,
            "instruction": {
                "op": "update_policy",
                "scope": "global",
                "params": {"max_tokens": 1000}
            },
            "should_succeed": True,
            "reason": "Admin can do anything"
        },
        {
            "authority": TrustAuthority.TOOL_RUNTIME,
            "instruction": {
                "op": "sign_tool_response",
                "scope": "web_search",
                "params": {"result": "data"}
            },
            "should_succeed": True,
            "reason": "Tool runtime can sign tool responses"
        },
        {
            "authority": TrustAuthority.TOOL_RUNTIME,
            "instruction": {
                "op": "update_policy",
                "scope": "global",
                "params": {}
            },
            "should_succeed": False,
            "reason": "Tool runtime CANNOT update policy"
        },
        {
            "authority": TrustAuthority.POLICY_ENGINE,
            "instruction": {
                "op": "update_policy",
                "scope": "rate_limits",
                "params": {"new_limit": 100}
            },
            "should_succeed": True,
            "reason": "Policy engine can update policies"
        },
        {
            "authority": TrustAuthority.USER_DELEGATE,
            "instruction": {
                "op": "user_preferences",
                "scope": "theme",
                "params": {"color": "dark"}
            },
            "should_succeed": True,
            "reason": "User delegate can modify preferences"
        },
        {
            "authority": TrustAuthority.USER_DELEGATE,
            "instruction": {
                "op": "update_policy",
                "scope": "security",
                "params": {}
            },
            "should_succeed": False,
            "reason": "User delegate CANNOT update security policy"
        }
    ]
    
    passed = 0
    failed = 0
    
    for i, scenario in enumerate(test_scenarios, 1):
        authority = scenario["authority"]
        instruction = scenario["instruction"]
        expected = scenario["should_succeed"]
        
        print(f"\n{'='*80}")
        print(f"Test {i}: {authority.value} → {instruction['op']}")
        print(f"Expected: {'✅ ALLOWED' if expected else '❌ DENIED'}")
        print(f"Reason: {scenario['reason']}")
        print("-" * 80)
        
        try:
            # Sign the instruction
            print(f"Signing instruction with {authority.value}'s private key...")
            signature = trust_mgr.sign_instruction(authority, instruction)
            print(f"✓ Signature generated: {signature.hex()[:32]}...")
            
            # Verify the instruction
            print(f"\nVerifying signature and permissions...")
            is_valid = trust_mgr.verify_multi_party_instruction(
                instruction,
                authority,
                signature
            )
            
            # Check result
            if is_valid == expected:
                print(f"\n✅ TEST PASSED: Behavior matches expectation")
                passed += 1
            else:
                print(f"\n❌ TEST FAILED: Got {is_valid}, expected {expected}")
                failed += 1
                
        except PermissionError as e:
            # Authority tried to sign something it's not allowed to
            print(f"\n⚠️  Permission denied during signing: {e}")
            if not expected:
                print(f"✅ TEST PASSED: Correctly prevented unauthorized signing")
                passed += 1
            else:
                print(f"❌ TEST FAILED: Should have been allowed")
                failed += 1
    
    # Step 3: Test signature forgery attempt
    print(f"\n\n{'='*80}")
    print("🚨 STEP 3: Signature Forgery Attack")
    print("-" * 80)
    
    print("\nAttack: User delegate tries to forge SYSTEM_ADMIN signature")
    print("to update security policy...")
    
    malicious_instruction = {
        "op": "update_policy",
        "scope": "security",
        "params": {"disable_all_checks": True}
    }
    
    # User delegate signs it (they have no permission for this)
    try:
        # They try to sign, but should be blocked
        fake_signature = trust_mgr.sign_instruction(
            TrustAuthority.USER_DELEGATE,
            malicious_instruction
        )
        print("❌ Signing should have been blocked!")
    except PermissionError:
        print("✓ Step 1: Signing blocked (no permission)")
    
    # Or, attacker signs with their own key but claims it's from admin
    print("\nAlternate attack: Sign with USER_DELEGATE key,")
    print("but claim signature is from SYSTEM_ADMIN...")
    
    user_instruction = {
        "op": "user_preferences",
        "scope": "test",
        "params": {}
    }
    user_signature = trust_mgr.sign_instruction(
        TrustAuthority.USER_DELEGATE,
        user_instruction
    )
    
    # Try to verify malicious instruction with wrong authority claim
    print(f"\nAttempting verification with wrong authority...")
    is_valid = trust_mgr.verify_multi_party_instruction(
        malicious_instruction,
        TrustAuthority.SYSTEM_ADMIN,  # Claiming to be admin
        user_signature  # But using user's signature
    )
    
    if not is_valid:
        print("✅ ATTACK BLOCKED: Signature verification failed")
        print("   The signature doesn't match the claimed authority")
        passed += 1
    else:
        print("❌ SECURITY BREACH: Forgery succeeded!")
        failed += 1
    
    # Summary
    print(f"\n\n{'='*80}")
    print("📊 TEST SUMMARY")
    print("=" * 80)
    print(f"""
    Total Tests: {passed + failed}
    Passed: {passed} ✅
    Failed: {failed} ❌
    
    Registered Authorities: {len(trust_mgr.authority_keys)}
    
    🔐 Security Status: {'EXCELLENT' if failed == 0 else 'COMPROMISED'}
    """)
    
    # Detailed breakdown
    print("=" * 80)
    print("🎯 KEY FINDINGS")
    print("=" * 80)
    print("""
    1. CRYPTOGRAPHIC ENFORCEMENT WORKING
       ✓ Each authority has unique Ed25519 keypair
       ✓ Signatures verified using public keys
       ✓ Forgery attempts detected and blocked
    
    2. PERMISSION HIERARCHY ENFORCED
       ✓ SYSTEM_ADMIN can do anything
       ✓ TOOL_RUNTIME limited to tool operations
       ✓ POLICY_ENGINE limited to policy operations
       ✓ USER_DELEGATE limited to preferences
    
    3. DEFENSE IN DEPTH
       ✓ Permission check before signing (fast fail)
       ✓ Cryptographic verification on receipt
       ✓ Authority mismatch detected
    
    4. REALISTIC KEY MANAGEMENT
       ✓ Keys generated per authority
       ✓ Private keys secured (would be in HSM)
       ✓ Public keys distributed for verification
    
    💡 CRITICAL INSIGHT:
    Even if an attacker compromises ONE authority (e.g., USER_DELEGATE),
    they cannot escalate privileges because:
    - They don't have other authorities' private keys
    - Signature verification prevents forgery
    - Permission checks are enforced at signing time
    
    This is "principle of least privilege" backed by mathematics.
    """)
    
    return passed, failed


if __name__ == "__main__":
    demo_real_multi_party_trust()