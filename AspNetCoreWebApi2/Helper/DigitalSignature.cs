using System;
using System.IO;
using System.Security.Cryptography;

namespace AspNetCoreWebApi2
{
	public class DigitalSignature : IDisposable
	{
		private int _keySize= 2048;
		private string _algorithm = "SHA256";
		private RSACryptoServiceProvider _rSACryptoServiceProvider;
		private RSAParameters _publicKey;
		private RSAParameters _privateKey;
		public DigitalSignature()	
		{
			_rSACryptoServiceProvider= new RSACryptoServiceProvider(_keySize);
		}
		public DigitalSignature(string algorithm)	
		{
			_algorithm= algorithm;
			_rSACryptoServiceProvider= new RSACryptoServiceProvider(_keySize);
		}
		public DigitalSignature(int keySize, string algorithm)
		{
			_keySize= keySize;
			_algorithm= algorithm;
			_rSACryptoServiceProvider= new RSACryptoServiceProvider(_keySize);
		}
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}
		public virtual void Dispose(bool disposing)
		{
			if(disposing)
			{
				if(_rSACryptoServiceProvider != null)				
				{
					_rSACryptoServiceProvider.Dispose();
				}
			}
		}
		public void GenerateNewKey() 
		{
			_rSACryptoServiceProvider.PersistKeyInCsp= false;
			_publicKey= _rSACryptoServiceProvider.ExportParameters(false);
			_privateKey= _rSACryptoServiceProvider.ExportParameters(true);
		}
		public void GenerateNewKey(string privateKeyPath, string publicKeyPath)
		{
			_rSACryptoServiceProvider.PersistKeyInCsp= false;
			ExportKeysInBlob(privateKeyPath, publicKeyPath);
		}
		public void ExportKeysInBlob(string privateKeyPath, string publicKeyPath)
		{
			File.WriteAllBytes(publicKeyPath, _rSACryptoServiceProvider.ExportCspBlob(false));
			File.WriteAllBytes(privateKeyPath, _rSACryptoServiceProvider.ExportCspBlob(true));
		}
		public void ExportKeysInXml(string privateKeyPath, string publicKeyPath)
		{
			File.WriteAllText(publicKeyPath, _rSACryptoServiceProvider.ToXmlString(false));
			File.WriteAllText(privateKeyPath, _rSACryptoServiceProvider.ToXmlString(true));
		}
		public void ImportPublicKeyInXml(string publickeyXml)
		{
			_rSACryptoServiceProvider.PersistKeyInCsp = false;
			_rSACryptoServiceProvider.FromXmlString(publickeyXml);
			_publicKey= _rSACryptoServiceProvider.ExportParameters(false);
		}
		public void ImportPrivateKeyInXml(string privateKeyXml)
		{
			_rSACryptoServiceProvider.PersistKeyInCsp = false;
			_rSACryptoServiceProvider.FromXmlString(privateKeyXml);
			_privateKey= _rSACryptoServiceProvider.ExportParameters(true);
		}
		public void ImportPublicKeyInBlob(string publicKey)
		{
			//byte[] publicKeyBytes = File.ReadAllBytes(publicKey);
			string publicKeyText= File.ReadAllText(publicKey);
			_rSACryptoServiceProvider.PersistKeyInCsp = false;
			//_rSACryptoServiceProvider.ImportCspBlob(publicKeyBytes);
			//_rSACryptoServiceProvider.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
			_rSACryptoServiceProvider.ImportFromPem(publicKeyText);
			_publicKey= _rSACryptoServiceProvider.ExportParameters(false);
		}
		public void ImportPrivateKeyInBlob(string privateKey)
		{
			byte[] privateKeyBytes = File.ReadAllBytes(privateKey);
			_rSACryptoServiceProvider.PersistKeyInCsp = false;
			//_rSACryptoServiceProvider.ImportCspBlob(privateKeyBytes);
			_rSACryptoServiceProvider.ImportRSAPrivateKey(privateKeyBytes, out _);
			_privateKey= _rSACryptoServiceProvider.ExportParameters(true);
		}
		
		public byte[] SignData(byte[] hashedDataToSign)
		{
			_rSACryptoServiceProvider.PersistKeyInCsp= false;
			_rSACryptoServiceProvider.ImportParameters(_privateKey);
			RSAPKCS1SignatureFormatter rSAPKCS1SignatureFormatter= new RSAPKCS1SignatureFormatter(_rSACryptoServiceProvider);
			rSAPKCS1SignatureFormatter.SetHashAlgorithm(_algorithm);
			return rSAPKCS1SignatureFormatter.CreateSignature(hashedDataToSign);
		}
		public bool VerifySignature(byte[] hashedData, byte[] signature)
		{
			_rSACryptoServiceProvider.ImportParameters(_publicKey);
			RSAPKCS1SignatureDeformatter rSAPKCS1SignatureDeformatter= new RSAPKCS1SignatureDeformatter(_rSACryptoServiceProvider);
			rSAPKCS1SignatureDeformatter.SetHashAlgorithm(_algorithm);
			return rSAPKCS1SignatureDeformatter.VerifySignature(hashedData, signature);
		}
	}
}