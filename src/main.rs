extern crate crypto;
extern crate rand;
extern crate rustc_serialize;

use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

use rustc_serialize::hex::{ToHex, FromHex};

use rand::{OsRng, Rng};

fn decrypt_aes(input: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
	let mut Operation = aes::cbc_decryptor(
		aes::KeySize::KeySize256,
		key,
		nonce,
		blockmodes::PkcsPadding);
	let mut done = Vec::<u8>::new();
	let mut buffer = [0, 1024];
	let mut input_buffer = buffer::RefReadBuffer::new(input);
	let mut output_buffer = buffer::RefWriteBuffer::new(&mut buffer);

	loop {
		let result = Operation.decrypt(&mut input_buffer, &mut output_buffer, true);
		done.extend(output_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
		match result {
			Err(why) => panic!("[-] Unable to encrypt: {:?}", why),
			Ok(result) => match result {
			BufferResult::BufferUnderflow => break,
			BufferResult::BufferOverflow => { }
			}
		}
	}
	Ok(done)
}

fn encrypt_aes(input: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
	let mut Operation = aes::cbc_encryptor(
		aes::KeySize::KeySize256,
		key,
		nonce,
		blockmodes::PkcsPadding);
	let mut done = Vec::<u8>::new();
	let mut buffer = [0, 1024];
	let mut input_buffer = buffer::RefReadBuffer::new(input);
	let mut output_buffer = buffer::RefWriteBuffer::new(&mut buffer);

	loop {
		let result = Operation.encrypt(&mut input_buffer, &mut output_buffer, true);
		done.extend(output_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
		match result {
			Err(why) => panic!("[-] Unable to decrypt data: {:?}", why),
			Ok(result) => match result {
			BufferResult::BufferUnderflow => break,
			BufferResult::BufferOverflow => { }	
			}
		}
	}
	Ok(done)
}
fn main() {
	// let mut pool = OsRng::new().ok().expect("[-] Error generating random number, aborting");
	let secret = "Hello World";
	let key = "cb6df50c50266c24006f7c6526c01d49e8ac44aa49d3418b419123269515b954".from_hex().unwrap();
	let mut nonce = "c1b793ec2f95083ace2442bf458e7ba8".from_hex().unwrap();
	let mut hmac = Hmac::new(Sha256::new(), &key);
	let ciphertext = encrypt_aes(secret.as_bytes(), &key, &nonce).ok().unwrap();
	let plaintext = decrypt_aes(&ciphertext[..], &key, &nonce).ok().unwrap();
	let hash = hmac.input(&ciphertext);
	let result = hmac.result();
	println!("HMAC Digest: {}", result.code().to_hex());
	println!("{}", key.to_hex());
	println!("{}", nonce.to_hex());
	println!("{}", ciphertext.to_hex());

}

