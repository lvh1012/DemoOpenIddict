using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

CreateEncryptionCertificate();

CreateSigningCertificate();

return;

void CreateEncryptionCertificate()
{
    using var algorithm = RSA.Create(keySizeInBits: 2048);
    const string fileName = "EncryptionCertificate.pfx";

    var subject = new X500DistinguishedName("CN=Fabrikam Server Encryption Certificate");
    var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));

    var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

    var folderPath = Path.Combine(Directory.GetParent(Directory.GetParent(Directory.GetParent(Environment.CurrentDirectory)!.FullName)!.FullName)!.FullName , "Certificates");
    Directory.CreateDirectory(folderPath);
    var filePath = Path.Combine(folderPath, fileName);
    File.WriteAllBytes(filePath, certificate.Export(X509ContentType.Pfx, string.Empty));
}

void CreateSigningCertificate()
{
    using var algorithm = RSA.Create(keySizeInBits: 2048);
    const string fileName = "SigningCertificate.pfx";

    var subject = new X500DistinguishedName("CN=Fabrikam Server Signing Certificate");
    var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

    var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

    var folderPath = Path.Combine(Directory.GetParent(Directory.GetParent(Directory.GetParent(Environment.CurrentDirectory)!.FullName)!.FullName)!.FullName , "Certificates");
    Directory.CreateDirectory(folderPath);
    var filePath = Path.Combine(folderPath, fileName);
    File.WriteAllBytes(filePath, certificate.Export(X509ContentType.Pfx, string.Empty));
}