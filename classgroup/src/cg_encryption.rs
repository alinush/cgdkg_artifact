//! CL-HSM encryption helpers: keygen, encrypt_all, decrypt.

use blstrs::Scalar;
use cpp_core::CppBox;

use bicycl::b_i_c_y_c_l::utils::{
    CLHSMCipherTextOfCLHSMqk as CipherText, CLHSMClearTextOfCLHSMqk as ClearText,
    CLHSMPublicKeyOfCLHSMqk as PublicKey, CLHSMSecretKeyOfCLHSMqk as SecretKey,
};
use bicycl::b_i_c_y_c_l::{CLHSMqk, Mpz, RandGen};
use bicycl::{
    CiphertextBox, MpzBox, PublicKeyBox, QFIBox, SecretKeyBox,
    VectorOfCLHSMClearTextOfCLHSMqk, VectorOfCLHSMPublicKeyOfCLHSMqk,
};
use bicycl::__ffi;

use crate::key_pop_zk::{create_pop_zk, PopZk, PopZkInstance};
use crate::utils::scalar_to_mpz;

pub fn encrypt_all(
    c: &CppBox<CLHSMqk>,
    rng_cpp: &mut CppBox<RandGen>,
    pks: &Vec<PublicKeyBox>,
    evaluations: Vec<Scalar>,
) -> (Vec<CiphertextBox>, MpzBox) {
    let ref_c: cpp_core::Ref<CLHSMqk> = unsafe { cpp_core::Ref::from_raw_ref(c) };

    let mut pks_cpp = unsafe { VectorOfCLHSMPublicKeyOfCLHSMqk::new() };
    for pk in pks {
        let ref_pk: cpp_core::Ref<PublicKey> = unsafe { cpp_core::Ref::from_raw_ref(&pk.0) };
        unsafe { pks_cpp.push_back(ref_pk) };
    }

    let mut evals_cleartext = unsafe { VectorOfCLHSMClearTextOfCLHSMqk::new() };
    for eval in &evaluations {
        let eval_mpz = unsafe { scalar_to_mpz(eval) };
        let cleartext = unsafe { ClearText::from_c_l_h_s_mqk_mpz(ref_c, &eval_mpz) };
        unsafe { evals_cleartext.push_back(&cleartext) };
    }

    let ref_pks_cpp: cpp_core::Ref<VectorOfCLHSMPublicKeyOfCLHSMqk> =
        unsafe { cpp_core::Ref::from_raw_ref(&pks_cpp) };
    let ref_cleartext: cpp_core::Ref<VectorOfCLHSMClearTextOfCLHSMqk> =
        unsafe { cpp_core::Ref::from_raw_ref(&evals_cleartext) };
    let r = unsafe { Mpz::new_copy(&rng_cpp.random_mpz(c.encrypt_randomness_bound())) };

    let ciphers = unsafe { c.encrypt_all_3a(ref_pks_cpp, ref_cleartext, &r) };

    let mut out = Vec::new();
    for i in 0..unsafe { ciphers.size() } {
        let ffi = unsafe {
            __ffi::ctr_bicycl_ffi_BICYCL__Utils_CL_HSM_CipherText_BICYCL_CL_HSMqk_CL_HSM_CipherText7(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::utils::CLHSMCipherTextOfCLHSMqk>>::cast_into(
                    ciphers.at(i),
                )
                .as_raw_ptr(),
            )
        };
        let cpp_cipher = unsafe { CppBox::from_raw(ffi) }
            .expect("attempted to construct a null CppBox");
        out.push(CiphertextBox(cpp_cipher));
    }

    (out, MpzBox(r))
}

pub fn decrypt(c: &CppBox<CLHSMqk>, sk: &SecretKeyBox, cipher: &CiphertextBox) -> MpzBox {
    let ref_sk: cpp_core::Ref<SecretKey> = unsafe { cpp_core::Ref::from_raw_ref(&sk.0) };
    let ref_cipher: cpp_core::Ref<CipherText> = unsafe { cpp_core::Ref::from_raw_ref(&cipher.0) };
    let mut cleartext = unsafe { c.decrypt(ref_sk, ref_cipher) };
    let cleartext_mpz = unsafe { cleartext.get_mpz() };
    MpzBox(cleartext_mpz)
}

pub fn keygen(
    c: &CppBox<CLHSMqk>,
    rng: &mut CppBox<RandGen>,
    associated_data: &Vec<u8>,
) -> (SecretKeyBox, PublicKeyBox, PopZk) {
    let mutref_rng: cpp_core::MutRef<RandGen> = unsafe { cpp_core::MutRef::from_raw_ref(rng) };
    let mut sk = unsafe { c.keygen_rand_gen(mutref_rng) };
    let pk = unsafe { c.keygen_c_l_h_s_m_secret_key_of_c_l_h_s_mqk(&sk) };

    let sk_mpz = unsafe { sk.get_mpz() };

    let ffi_gen_h = unsafe {
        __ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
            cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(c.h())
                .as_raw_ptr(),
        )
    };
    let gen_h = unsafe { CppBox::from_raw(ffi_gen_h) }
        .expect("attempted to construct a null CppBox");

    let instance = PopZkInstance {
        gen: QFIBox(gen_h),
        public_key: PublicKeyBox(pk),
        associated_data: associated_data.clone(),
    };
    let pop = create_pop_zk(&instance, &sk_mpz, c, rng).unwrap();

    (SecretKeyBox(sk), instance.public_key, pop)
}
