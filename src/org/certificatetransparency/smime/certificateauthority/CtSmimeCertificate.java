package org.certificatetransparency.smime.certificateauthority;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.List;

public class CtSmimeCertificate implements Serializable {
    static final long serialVersionUID = -50077493051991107L;

    String sctEncryption;
    String sctSignature;
    List<Certificate> encryptionCertificate;
    List<Certificate> signatureCertificate;

    public String getSctEncryption() {
        return sctEncryption;
    }

    public void setSctEncryption(String sctEncryption) {
        this.sctEncryption = sctEncryption;
    }

    public String getSctSignature() {
        return sctSignature;
    }

    public void setSctSignature(String sctSignature) {
        this.sctSignature = sctSignature;
    }

    public List<Certificate> getEncryptionCertificate() {
        return encryptionCertificate;
    }

    public void setEncryptionCertificate(List<Certificate> encryptionCertificate) {
        this.encryptionCertificate = encryptionCertificate;
    }

    public List<Certificate> getSignatureCertificate() {
        return signatureCertificate;
    }

    public void setSignatureCertificate(List<Certificate> signatureCertificate) {
        this.signatureCertificate = signatureCertificate;
    }

    public CtSmimeCertificate() {
    }
}
