import { asn1, pkcs12, pki, util } from "node-forge";

export function getPrivateKeyFromBase64DER(base64der: string) {
  const der = util.decode64(base64der);
  const asn1String = asn1.fromDer(der);
  const pkcs12Pfx: pkcs12.Pkcs12Pfx = pkcs12.pkcs12FromAsn1(asn1String);
  const keyBagCollection = pkcs12Pfx.getBags({
    bagType: pki.oids.pkcs8ShroudedKeyBag,
  });
  const pkcs8ShroudedKeyBag = keyBagCollection[pki.oids.pkcs8ShroudedKeyBag][0];
  const rsaPrivateKey = pki.privateKeyToAsn1(pkcs8ShroudedKeyBag.key);
  const privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);
  const pemCertificate = pki.privateKeyInfoToPem(privateKeyInfo);
  return pemCertificate;
}
