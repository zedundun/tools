package main

import(
 "crypto/aes"
 "crypto/cipher"
 "crypto/rand"
 "encoding/hex"
 "fmt"
)

func GenerateRandomBytes(length int) []byte{
  bytes:=make([]byte,length)
  _,err:=rand.Read(bytes)
  if err!=nil{
    fmt.Println(err)
  }
  return bytes
}

func EncryptWithKey(plaintext []byte, key []byte) []byte {
  block,err:=aes.NewCipher(key)
  if err!=nil{
    fmt.Println(err)
  }
  nonce:=GenerateRandomBytes(12)
  aesgcm,err:=cipher.NewGCM(block)
  if err!=nil{
    fmt.Println(err)
  }
  ciphertext:=aesgcm.Seal(nonce,nonce,plaintext,nil)
  return ciphertext
}

func DecryptWithKey(ciphertext []byte, key []byte) ([]byte,error){
  var block cipher.Block
  var err error
  block,err=aes.NewCipher(key)
  if err!=nil{
    fmt.Println(err)
    return []byte{},err
  }
  aesgcm,err:=cipher.NewGCM(block)
  if err!=nil{
    fmt.Println(err)
    return []byte{},err
  }
  nonce,ciphertext:=ciphertext[:12],ciphertext[12:]
  plaintext,err:=aesgcm.Open(nil,nonce,ciphertext,nil)
  if err!=nil{
    fmt.Println(err)
    return []byte{},err
  }
  return plaintext,nil
}

func main(){
  plaintext:="123456"
  key:=GenerateRandomBytes(32)  //for AES256
  keyStr:=hex.EncodeToString(key)
  fmt.Println("key:",key)
  fmt.Println("keyStr:",keyStr)
  
  cipher:=EncryptWithKey([]byte(plaintext),key)
  cipherStr:=hex.EncodeToString(cipher)
  fmt.Println("Cipher bytes:\n",cipher)
  fmt.Println("Cipher Hex:\n", cipherStr )
  
  bKey,_:=hex.DecodeString(keyStr)
  bCipher,_:=hex.DecodeString(cipherStr)
  newPlainText:=DecryptWithKey(bCipher,bKey)
  fmt.Println("plaintext:",string(newPlainText))
}
