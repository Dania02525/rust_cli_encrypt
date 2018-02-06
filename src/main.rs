extern crate rand;
extern crate crypto;
extern crate data_encoding;


use std::io;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use rand::{ Rng, OsRng };
use data_encoding::BASE64;

fn main() {
    println!("Encrypt (e) or Decrypt (d)");

    let mut mode = String::new();
    let mut input = String::new();
    let mut key = String::new();

    io::stdin().read_line(&mut mode)
        .expect("Failed to read line");

    let mode = mode.trim().to_string();

    if mode == "e".to_string() {
        println!("Enter string to be encrypted");
        io::stdin().read_line(&mut input)
            .expect("Failed to read line");

        let input = input.trim().to_string();

        println!("Enter strong passphrase");
        io::stdin().read_line(&mut key)
            .expect("Failed to read line");

        let key = key.trim().to_string();

        let result = encrypted_string(input, key);

        println!("Encrypted: {:?}", result);

    } else if mode == "d".to_string() {
        println!("Enter string to be decrypted");
        io::stdin().read_line(&mut input)
            .expect("Failed to read line");

        let input = input.trim().to_string();

        println!("Enter the passphrase");
        io::stdin().read_line(&mut key)
            .expect("Failed to read line");

        let key = key.trim().to_string();

        let result = decrypted_string(input, key);

        println!("Decrypted: {:?}", result);

    } else {
        println!("The mode {} is not supported", mode);
    }
}

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    // Create an encryptor instance of the best performing
    // type available for the platform.
    let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

    // Each encryption operation encrypts some data from
    // an input buffer into an output buffer. Those buffers
    // must be instances of RefReaderBuffer and RefWriteBuffer
    // (respectively) which keep track of how much data has been
    // read from or written to them.
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // Each encryption operation will "make progress". "Making progress"
    // is a bit loosely defined, but basically, at the end of each operation
    // either BufferUnderflow or BufferOverflow will be returned (unless
    // there was an error). If the return value is BufferUnderflow, it means
    // that the operation ended while wanting more input data. If the return
    // value is BufferOverflow, it means that the operation ended because it
    // needed more space to output data. As long as the next call to the encryption
    // operation provides the space that was requested (either more input data
    // or more output space), the operation is guaranteed to get closer to
    // completing the full operation - ie: "make progress".
    //
    // Here, we pass the data to encrypt to the enryptor along with a fixed-size
    // output buffer. The 'true' flag indicates that the end of the data that
    // is to be encrypted is included in the input buffer (which is true, since
    // the input data includes all the data to encrypt). After each call, we copy
    // any output data to our result Vec. If we get a BufferOverflow, we keep
    // going in the loop since it means that there is more work to do. We can
    // complete as soon as we get a BufferUnderflow since the encryptor is telling
    // us that it stopped processing data due to not having any more data in the
    // input buffer.
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn encrypted_string(text: String, key: String) -> String {
    let mut iv = "whatever".as_bytes();
    // let mut rng = OsRng::new().ok().unwrap();
    // rng.fill_bytes(&mut iv);
    let result = encrypt(text.as_bytes(), &key.as_bytes(), &iv).ok().unwrap();
    let output = BASE64.encode(&result);
    output
}

fn decrypted_string(encrypted_text: String, key: String) -> String {
    let mut iv = "whatever".as_bytes();
    // let mut rng = OsRng::new().ok().unwrap();
    // rng.fill_bytes(&mut iv);
    let encrypted_data = BASE64.decode(&encrypted_text.as_bytes()).ok().unwrap();

    let mut result = decrypt(&encrypted_data[..], &key.as_bytes(), &iv).ok().unwrap();

    println!("debug: {:?}", result);
    println!("debug: {:?}", String::from_utf8(result).unwrap());
    let output = "foo".to_string();
    output
}
