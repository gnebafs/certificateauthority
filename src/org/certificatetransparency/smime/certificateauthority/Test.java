package org.certificatetransparency.smime.certificateauthority;

import org.apache.commons.codec.binary.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Test {
 public static void main(String[] argv) throws ParseException{
	 JSONObject jsonObject = new JSONObject();
		jsonObject.put("encryptionCertificate", "Encryption");
		jsonObject.put("signatureCertificate", "Signature");
		String s= "add"+jsonObject.toString();
		
		if(s.startsWith("add"))
		{
			String sb=org.apache.commons.lang.StringUtils.remove(s, "add");
			JSONParser parser = new JSONParser();
			Object obj = parser.parse(sb);
			JSONObject obj2 = (JSONObject) (obj);

			String commonName = (String) obj2.get("encryptionCertificate");
			String commonName1 = (String) obj2.get("signatureCertificate");
			
			System.out.println(commonName1);
			System.out.println(commonName);
			
		}
 }
}
