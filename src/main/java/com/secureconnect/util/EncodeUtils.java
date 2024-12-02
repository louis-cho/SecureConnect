package com.secureconnect.util;

import java.util.Base64;

public class EncodeUtils {

 public static String getBase64(byte[] bytes) {
	 return Base64.getEncoder().encodeToString(bytes);
 }
}
