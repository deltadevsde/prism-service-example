use std::sync::Arc;

use keystore_rs::{KeyChain, KeyStore as _};
use log::debug;
use prism_client::{
    binary::ToBinary as _, Account, PendingTransaction as _, PrismApi as _, SignatureBundle,
    SigningKey, VerifyingKey,
};
use prism_prover::Prover;

use anyhow::{anyhow, Result};

use crate::SERVICE_ID;

async fn register_service(prover: Arc<Prover>) -> Result<()> {
    // First, we make sure the service is not already registered.
    if prover.get_account(SERVICE_ID).await?.account.is_some() {
        debug!("Service already registered.");
        return Ok(());
    }

    // Next we use our keystore crate to get/create a new private key for the service.
    // By default, this is stored in the operating system's keychain.
    let keystore_sk = KeyChain
        .get_signing_key(SERVICE_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let sk = SigningKey::Ed25519(Box::new(keystore_sk));
    let vk: VerifyingKey = sk.verifying_key();

    // Now we create the operation to register the service. Under the hood, this
    // creates a prism account that links the service's public key to the
    // service id -- only allowing this keypair to authorize account creations
    // from the service.
    debug!("Submitting transaction to register test service");
    prover
        .register_service(SERVICE_ID.to_string(), vk, &sk)
        .await?
        .wait()
        .await?;

    Ok(())
}

async fn add_key(
    user_id: String,
    prover: Arc<Prover>,
    signing_key: SigningKey,
    new_key: VerifyingKey,
) -> Result<Account> {
    if let Some(account) = prover.get_account(&user_id).await?.account {
        debug!("Submitting transaction to add key to account {}", &user_id);

        let updated_account = prover
            .add_key(&account, new_key, &signing_key)
            .await?
            .wait()
            .await?;

        return Ok(updated_account);
    };

    Err(anyhow!("Account {} not found", &user_id))
}

async fn add_data(
    user_id: String,
    prover: Arc<Prover>,
    signing_key: SigningKey,
    data: Vec<u8>,
    data_signature: SignatureBundle,
) -> Result<Account> {
    if let Some(account) = prover.get_account(&user_id).await?.account {
        // The source of this data can either be signed by one of the user's
        // existing keys, or from an external signer referenced in
        // data_signature.
        debug!("Submitting transaction to add data to account {}", &user_id);
        let updated_account = prover
            .add_data(&account, data, data_signature, &signing_key)
            .await?
            .wait()
            .await?;

        return Ok(updated_account);
    };

    Err(anyhow!("Account {} not found", &user_id))
}

async fn create_account(user_id: String, prover: Arc<Prover>) -> Result<Account> {
    // First, we make sure the account is not already registered.
    if let Some(account) = prover.get_account(&user_id).await?.account {
        debug!("Account {} exists already", &user_id);
        return Ok(account);
    }

    // We retrieve the test service's private key to authorize the account creation.
    let service_keystore = KeyChain
        .get_signing_key(SERVICE_ID)
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;

    let service_sk = SigningKey::Ed25519(Box::new(service_keystore));

    // We retrieve/create the user's keypair to create the account.
    // Note: Obviously, in the real world, the keypair would be handled client side.
    let user_keystore = KeyChain
        .get_signing_key(&format!("{}/{}", user_id, SERVICE_ID))
        .map_err(|e| anyhow!("Error getting key from store: {}", e))?;
    let user_sk = SigningKey::Ed25519(Box::new(user_keystore));
    let user_vk: VerifyingKey = user_sk.verifying_key();

    // Here we use the alternative API: The request builder.
    // We do this here to demonstrate the example where you can't pass a signing
    // key from the user - which should be the case for most applications.
    let unsigned_tx = prover
        .build_request()
        .create_account()
        .with_id(user_id.clone())
        .with_key(user_vk.clone())
        .for_service_with_id(SERVICE_ID.to_string())
        .meeting_signed_challenge(&service_sk)?
        .transaction();

    // The user must sign the transaction. In a real world application, these
    // `bytes_to_sign` would be returned to the user for signing.
    let bytes_to_sign = unsigned_tx.encode_to_bytes()?;
    let signed_tx = user_sk.sign(bytes_to_sign);

    let signature_bundle = SignatureBundle {
        verifying_key: user_vk.clone(),
        signature: signed_tx,
    };
    let tx = unsigned_tx.externally_signed(signature_bundle);

    // Because the account is new, we create an empty account to store the transaction.
    let mut account = Account::default();
    account.process_transaction(&tx)?;

    debug!("Submitting transaction to create account {}", &user_id);
    prover.clone().validate_and_queue_update(tx.clone()).await?;

    Ok(account)
}
