package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/omept/secure-file-transfer/utils/checkerr"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file") // create a .env file with the attached .env.example as template
	}

	if len(os.Args) != 2 {
		log.Fatalf("required format %s address:port\n", os.Args[0])
	}

	// validate address structure
	addr, err := net.ResolveTCPAddr("tcp", os.Args[1])
	checkerr.Check(err)

	conn, err := net.DialTCP("tcp", nil, addr)
	checkerr.Check(err)
	defer conn.Close()
	var bucket [10268]byte // Although the server reads from the sent file in chuncks of [1024*10]byte array (10kb), the resulting AES-256 encrypted version is larger on completion of each chuck. I used the exact size for the AES-256 encryted version of a [1024*10]byte array to aviod discripancies during decryption. I.e, I get a [10268] byte array when I encrypt a [10240]byte array AES-256. I'm running on my non M chip Macbook pro.
	//👆🏽 pro tip: the extra 28byte is the size of the initialization vector (nonce). Go's implementation probably uses  Galois/Counter Mode for the initialization vector (nonce)

	start := time.Now()
	key := os.Getenv("ENCRYPT_DECRYPT_KEY")
	df := os.Getenv("DECRPTED_FILE_NAME")

	//create the response file
	tmpName := "tmpholderforfile.customextension"
	_ = os.Remove(tmpName)
	file, err := os.Create(tmpName)
	checkerr.Check(err)
	for {
		n, err := conn.Read(bucket[:])

		if err == io.EOF || n == 0 {
			break
		}
		if err != nil {
			log.Println("conn error: ", err.Error())
			break
		}
		log.Printf("read encrypted %d bytes \n", n)
		decrypted, err := decrypt(bucket[:n], key)

		if err != nil {
			log.Printf("read %d bytes \n", n)

			log.Println("encrypt decrypt error: ", err)
			break
		}
		// log.Println("bytes decrypted: ", decrypted)
		nf, err := file.WriteString(string(decrypted))
		if err != nil {
			log.Printf("error:  %v \n", err)
			break
		}
		log.Printf("wrote %d bytes to tmp file\n", nf)
	}

	file.Close()
	os.Rename(tmpName, df)
	log.Printf("✅ Video received and decrypted in %v", time.Since(start))

}

// decrypt decrypts a AES encrypted byte slice from the recipient server and returns the original byte slice
func decrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
