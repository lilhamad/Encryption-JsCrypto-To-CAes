using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace Encryption
{
    class EncryptionService
    {
        private string aesKey;
        private string ivKey;
        private string algorithm;

        public EncryptionService(string aesKey, string ivKey)
        {
            this.aesKey = aesKey;
            this.ivKey = ivKey;
            this.algorithm = "aes-128-cbc";
        }


        public string encrypt(string dataToBeEncrypted)
        {
            if (dataToBeEncrypted.GetType().Name !== "string")
            {
                Console.WriteLine(Cypher.encrypt: argument must be string; objects must must be stringified");
            }
            const cypher = Aes.Create(this.algorithm, Buffer.from(this.aesKey), this.ivKey);
            const encrypted = c.ypher.update(dataToBeEncrypted);
            const encryptedData = Buffer.concat([encrypted, cypher.final()]);
            return encryptedData.toString('hex');
        }

        public string decrypt(encryptedData)
        {
            if (typeof encryptedData !== 'string')
            {
                throw new Error('Cypher.decrypt error: argument must be string');
            }
            const decipher = crypto.createDecipheriv(
            this.algorithm,
            Buffer.from(this.aesKey),
            this.ivKey
            );
            const encryptedText = Buffer.from(encryptedData, 'hex');
            const decrypted = decipher.update(encryptedText);
            const decryptedData = Buffer.concat([decrypted, decipher.final()]);
            return decryptedData.toString();
        }

        //var encrypter = new Cypher(aesKey, ivKey);
        //// to encrypt
        //encrypter.encrypt(DATA);

        //// to decrypt
        //encrypter.decrypt(DATA);

        public encodeSha256() {
            var hash = crypto.createHash('sha256');
            hash.update(ICAD_USERNAME + date + ICAD_USER_PASSWORD);
            return hash.digest('hex');
        }

        public void createRequestHeader(){
            var ContentType = "text/plain";
            var SIGNATURE = "crypto.encodeSha256()";
            var SIGNATURE_METH = "SHA256";
            var TIMESTAMP = "crypto.timeStamp()";
            var Authorization = "Buffer.from";
        }
    }

    public class RequestHeader
    {
        public string ContentType { get; set; }
    }
}
