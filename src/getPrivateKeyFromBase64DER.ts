// node-forge appears to still be a CommonJS module which causes issues when used from a calling ESM Module
// This syntax resolves them
import pkg from "node-forge";
const { asn1, pki, util } = pkg;

export function getPrivateKeyFromBase64DER(base64der: string) {
  const der = util.decode64(base64der);
  const asn1String = asn1.fromDer(der);
  const pkcs12Pfx: pkg.pkcs12.Pkcs12Pfx = pkg.pkcs12.pkcs12FromAsn1(asn1String);
  const keyBagCollection = pkcs12Pfx.getBags({
    bagType: pki.oids.pkcs8ShroudedKeyBag,
  });
  const pkcs8ShroudedKeyBag = keyBagCollection[pki.oids.pkcs8ShroudedKeyBag][0];
  const rsaPrivateKey = pki.privateKeyToAsn1(pkcs8ShroudedKeyBag.key);
  const privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);
  const pemCertificate = pki.privateKeyInfoToPem(privateKeyInfo);
  return pemCertificate;
}
