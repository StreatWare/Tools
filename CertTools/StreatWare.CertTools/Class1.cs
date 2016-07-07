using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;

namespace StreatWare.CertTools
{
    public class SelfSignedCertificateGenerator
    {
        private string _subjectName;
        private string _issuerName;
        private BigInteger _serialNumber;
        private DateTime? _startDate;
        private DateTime? _endDate;
        private int _keyStrength = 4096;
        private SecureRandom _random;
        private int DefaultMonthsValid = 2;
        private X509V3CertificateGenerator _certificateGenerator;
        private AsymmetricCipherKeyPair _subjectKeyPair;

        public string SubjectName
        {
            get { return _subjectName; }
            set{ _subjectName = value.StartsWith("CN=", StringComparison.InvariantCultureIgnoreCase) ? value :  $"CN={value}"; }
        }

        public string IssuerName
        {
            get { return _issuerName ?? _subjectName; }
            set { _issuerName = value.StartsWith("CN=", StringComparison.InvariantCultureIgnoreCase) ? value : $"CN={value}"; }
        }

        public BigInteger SerialNumber
        {
            get { return _serialNumber == null ? BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), _random) : _serialNumber; }
            set { _serialNumber = value; }
        }
        
        public DateTime StartDate
        {
            get { return _startDate ?? DateTime.Now; }
            set { _startDate = value; }
        }

        public DateTime EndDate
        {
            get { return _endDate ?? StartDate.AddMonths(DefaultMonthsValid); }
            set { _endDate = value; }
        }

        public int KeyStrength
        {
            get { return _keyStrength; }
            set { _keyStrength = value; }
        }

        public X509Certificate2 Generate(string subjectName, string issuerName, DateTime startDate, DateTime endDate)
        {
            SubjectName = subjectName;
            IssuerName = issuerName;
            StartDate = startDate;
            EndDate = endDate;

            return Generate();
        }

        public X509Certificate2 Generate(string subjectName, string issuerName)
        {
            SubjectName = subjectName;
            IssuerName = issuerName;

            return Generate();
        }

        public X509Certificate2 Generate(string subjectName)
        {
            SubjectName = subjectName;

            return Generate();
        }

        public X509Certificate2 Generate()
        {
            if (string.IsNullOrWhiteSpace(SubjectName))
            {
                throw new InvalidOperationException("Subject name not set.");
            }

            _certificateGenerator = new X509V3CertificateGenerator();

            GenerateSecretRandom();
            SetCertificateProperties();
            return GenerateCertificate();

            throw new NotImplementedException();
        }

        private void GenerateSecretRandom()
        {
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            _random = new SecureRandom(randomGenerator);
        }

        private void CreateRsaKeyPair()
        {
            var keyGenerationParameters = new KeyGenerationParameters(_random, KeyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            _subjectKeyPair = keyPairGenerator.GenerateKeyPair();
        }

        private void SetCertificateProperties()
        {
            _certificateGenerator.SetSubjectDN(new X509Name(SubjectName));
            _certificateGenerator.SetIssuerDN(new X509Name(IssuerName));
            _certificateGenerator.SetSerialNumber(SerialNumber);
            _certificateGenerator.SetNotBefore(StartDate.ToUniversalTime());
            _certificateGenerator.SetNotAfter(EndDate.ToUniversalTime());
            _certificateGenerator.SetPublicKey(_subjectKeyPair.Public);
        }

        private X509Certificate2 GenerateCertificate()
        {
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", _subjectKeyPair.Private, _random);
            
            // Generate self-signed certificate
            Org.BouncyCastle.X509.X509Certificate certificate = _certificateGenerator.Generate(signatureFactory);
            var x509 = new X509Certificate2(certificate.GetEncoded());

            // Set private key
            x509.PrivateKey = DotNetUtilities.ToRSA(_subjectKeyPair.Private as RsaPrivateCrtKeyParameters);

            return x509;
        }
    }
}
