# CryptoGraphy
Put the available modle class and helper class in to your android code 

#Example usage of this class
 # Encryption
 * mCryptoModel=CryptoWithPassword.getInstance().encrypt(Password,PlainText);
 # Decryption
 * mCryptoModel=CryptoWithPassword.getInstance().decrypt(Password,mCryptoModel);//mCryptomodel should contain its salt,IV and the encrypted data

We are using PBEWithSHA256And256BitAES-CBC-BC algorithm 
You will get private key in the returning object of Encrypt method 
With that private key only you can decrypt that data 
Password is choise of yours ,That will be your public key
 
