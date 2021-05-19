package org.committee.insCCP.servers;

import org.apache.commons.codec.binary.*;
import org.committee.insCCP.dataSets.User;

import com.mysql.cj.conf.ConnectionUrl.Type;

import javax.crypto.Cipher;
import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


public class utils {
	
	public static class PackageUtils {	
		
		public static ArrayList<byte[]> SecondaryPack(byte[] src, int blockSize) {
			ArrayList<byte[]> resArrayList = new ArrayList<>();
			
			byte[] md5 = MD5Utils.MD5Byte(src);
			
			if(blockSize <= md5.length + 1) return null;
			
			for(int i = 0;i < src.length;i += (blockSize - 1 - md5.length)) {
				
				byte[] temp = Convertion.BytesExpand(blockSize, md5);
				
				temp[md5.length] = 1;
				
				for(int j = md5.length + 1;j < blockSize;++j) {
					if(i + j - md5.length - 1 < src.length) temp[j] = src[i + j - md5.length - 1];
				}
				
				resArrayList.add(temp);
				
			}
			
			byte[] eof = Convertion.BytesExpand(blockSize, md5);
			
			eof[md5.length] = 0;
			
			resArrayList.add(eof);
			
			return resArrayList;
		}
		
		public static byte[] SecondaryUnPack(ArrayList<byte[]> src, int BANDWIDTH) {
			byte[] res = new byte[src.size() * BANDWIDTH];
			
			int offset = 0;
			
			for(byte[] frag : src) {
				if(frag[16] == 0) break;
				for(int i = 17;i < frag.length;++i) {
					res[offset] = frag[i];
					offset++;
				}
			}
			
			return res;
		}
		
		public static Map<String, String> readMD5andState(ByteBuffer data) {
			
			Map<String, String> resMap = new HashMap<String, String>();
			
			byte[] md5 = new byte[16];
			
			data.get(md5, 0, 16);
			
			resMap.put("MD5",Hex.encodeHexString(md5));
			
			resMap.put("info", "" + data.get(16));
			
			return resMap;
			
		}
		
		public static byte[] filePack(String id, String name, byte[] file, String privateKey) {
			
			byte[] id_RSA, name_RSA, file_RSA;
			try {
				id_RSA = RSAUtils.privateEncrypt(id.getBytes(Charset.forName("UTF-8")), RSAUtils.getPrivateKey(privateKey));
				name_RSA = RSAUtils.privateEncrypt(name.getBytes(Charset.forName("UTF-8")), RSAUtils.getPrivateKey(privateKey));
				file_RSA = RSAUtils.privateEncrypt(file, RSAUtils.getPrivateKey(privateKey));
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				e.printStackTrace();
				return null;
			}
	    	
			byte[] data = new byte[2 + 4 + 4 + 4 + id_RSA.length + name_RSA.length + file_RSA.length];
			
			data[0] = 6;
			
			byte[] size1 = Convertion.int2Bytes(id_RSA.length), 
					size2 = Convertion.int2Bytes(file_RSA.length), 
					size3 = Convertion.int2Bytes(name_RSA.length);
			
			for(int i = 0;i < 4;++i) {
				data[2 + i] = size1[i];
				data[6 + i] = size3[i];
				data[10 + i] = size2[i];
			}
			
			for(int i = 0;i < id_RSA.length;++i) {
				data[2 + 4 + 4 + 4 + i] = id_RSA[i];
			}
			
			for(int i = 0;i < name_RSA.length;++i) {
				data[2 + 4 + 4 + 4 + id_RSA.length + i] = name_RSA[i];
			}
			
			for(int i = 0;i < file_RSA.length;++i) {
				data[2 + 4 + 4 + 4 + id_RSA.length + name_RSA.length + i] = file_RSA[i];
			}
			
			return data;
		}
		
		public static Map<String, Object> fileUnPack(ByteBuffer msg, String publicKey) {
			Map<String, Object> resMap = new HashMap<>();
			
			byte[] data = msg.array().clone(), 	
					id = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 2, 4))], 
					name = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 6, 4))],
					message = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 10, 4))];
			
			for(int i = 0;i < id.length;++i) id[i] = data[14 + i];
			for(int i = 0;i < name.length;++i) name[i] = data[14 + id.length + i];
			for(int i = 0;i < message.length;++i) message[i] = data[14 + id.length + name.length + i];
			
			try {
				resMap.put("name", new String(RSAUtils.publicDecrypt(name, RSAUtils.getPublicKey(publicKey)), Charset.forName("UTF-8")));
				resMap.put("file", RSAUtils.publicDecrypt(message, RSAUtils.getPublicKey(publicKey)));
				resMap.put("id", new String(RSAUtils.publicDecrypt(id, RSAUtils.getPublicKey(publicKey)), Charset.forName("UTF-8")));
			} catch (Exception e) {
				e.printStackTrace();
			}
			return resMap;
			
		}
		
		public static byte[] friendListPack(byte friendType, ArrayList<User> friends, boolean[] onLine, String privateKey) {
			
			byte[] friends_RSA;
			
			StringBuilder friend_PretreatString = new StringBuilder();
			
			for(int i = 0;i < friends.size();++i) {
				friend_PretreatString.append(friends.get(i).toString() + (onLine == null ? "" : (onLine[i] ? "@1" : "@0")) +  "\n");
			}
			
			try {
				friends_RSA = RSAUtils.privateEncrypt(friend_PretreatString.toString().getBytes(Charset.forName("UTF-8")), RSAUtils.getPrivateKey(privateKey));
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				e.printStackTrace();
				return null;
			}
	    	
			byte[] data = new byte[6 + 4 + friends_RSA.length];
			
			data[0] = 5;
			
			data[1] = friendType;
			
			byte[] size1 = Convertion.int2Bytes(friends_RSA.length);
			
			for(int i = 0;i < 4;++i) {
				data[2 + i] = size1[i];
			}
			
			for(int i = 0;i < friends_RSA.length;++i) {
				data[2 + 4 + i] = friends_RSA[i];
			}
			
			return data;
		}
		
		public static ArrayList<String> friendListUnPack(ByteBuffer msg, String publicKey) {
			
			ArrayList<String> resArray = new ArrayList<String>();
			
			byte[] data = msg.array(), 
					
			friendList = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 2, 4))];
			
			for(int i = 0;i < friendList.length;++i) friendList[i] = data[6 + i];
			
			try {
				String friendString = new String(RSAUtils.publicDecrypt(friendList, RSAUtils.getPublicKey(publicKey)), Charset.forName("UTF-8"));
				
				String[] temp = friendString.split("\n");
				
				for(String string : temp) {
					String[] temp2 = string.split("@");
					resArray.add(temp2[1]);
				}
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				e.printStackTrace();
			}
			return resArray;
			
		}
		
		public static byte[] messagePack(String id, byte msgType, String msg, String privateKey) {
			
			byte[] id_RSA, msg_RSA;
			try {
				id_RSA = RSAUtils.privateEncrypt(id.getBytes(Charset.forName("UTF-8")), RSAUtils.getPrivateKey(privateKey));
				msg_RSA = RSAUtils.privateEncrypt(msg.getBytes(Charset.forName("UTF-8")), RSAUtils.getPrivateKey(privateKey));
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				e.printStackTrace();
				return null;
			}
	    	
			byte[] data = new byte[2 + 4 + 4 + id_RSA.length + msg_RSA.length];
			
			data[0] = 3;
			
			data[1] = msgType;
			
			byte[] size1 = Convertion.int2Bytes(id_RSA.length), 
					size2 = Convertion.int2Bytes(msg_RSA.length);;
			
			for(int i = 0;i < 4;++i) {
				data[2 + i] = size1[i];
				data[6 + i] = size2[i];
			}
			
			for(int i = 0;i < id_RSA.length;++i) {
				data[2 + 4 + 4 + i] = id_RSA[i];
			}
			
			for(int i = 0;i < msg_RSA.length;++i) {
				data[2 + 4 + 4 + id_RSA.length + i] = msg_RSA[i];
			}
			
			return data;
		}
		
		public static Map<String, String> messageUnPack(ByteBuffer msg, String publicKey) {
			Map<String, String> resMap = new HashMap<>();
			
			byte[] data = msg.array(), 
					
			id = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 2, 4))], 
			message = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 6, 4))];
			for(int i = 0;i < id.length;++i) id[i] = data[10 + i];
			for(int i = 0;i < message.length;++i) message[i] = data[10 + id.length + i];
			
			try {
				resMap.put("id", new String(RSAUtils.publicDecrypt(id, RSAUtils.getPublicKey(publicKey)), Charset.forName("UTF-8")));
				resMap.put("message", new String(RSAUtils.publicDecrypt(message, RSAUtils.getPublicKey(publicKey)), Charset.forName("UTF-8")));
				resMap.put("msgType", "" + data[1]);
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				e.printStackTrace();
			}
			return resMap;
			
		}
		
		public static byte[] errorPack(byte subStatus, String msg) {
	    	
			byte[] data = ("xxaaaa" + msg).getBytes(Charset.forName("UTF-8"));
			
			data[0] = 4;
			
			data[1] = subStatus;
			
			byte[] size = Convertion.int2Bytes(msg.getBytes(Charset.forName("UTF-8")).length);
							
			for(int i = 0;i < 4;++i) {
				data[2 + i] = size[i];
			}
			
			return data;
		}
		
		public static Map<String, String> errorUnPack(ByteBuffer error) {
			Map<String, String> resMap = new HashMap<>();
			byte[] data = error.array(), 
					msg = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 2, 4))];
			
			for(int i = 0;i < msg.length;++i) msg[i] = data[6 + i];
			
			resMap.put("subStatus", "" + data[1]);
			resMap.put("message", new String(msg, Charset.forName("UTF-8")));
			return resMap;
		}
	
		public static byte[] loginSuccessPack(String publicKey, String privateKey) {
	    	
			byte[] signInData = ("xaaaabbbb" + publicKey + privateKey).getBytes(Charset.forName("UTF-8"));
			
			signInData[0] = 1;
			
			byte[] size1 = Convertion.int2Bytes(publicKey.getBytes(Charset.forName("UTF-8")).length), 
					size2 = Convertion.int2Bytes(privateKey.getBytes(Charset.forName("UTF-8")).length);;
			
			for(int i = 0;i < 4;++i) {
				signInData[1 + i] = size1[i];
				signInData[5 + i] = size2[i];
			}
			
			return signInData;
		}
		
		public static Map<String, String> loginSucessUnPack(ByteBuffer loginPackage) {
			Map<String, String> resMap = new HashMap<>();
			byte[] data = loginPackage.array(), 
					publicKey = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 1, 4))], 
					privateKey = new byte[Convertion.bytes2Int(Convertion.BytesCapture(data, 5, 4))];
			for(int i = 0;i < publicKey.length;++i) publicKey[i] = data[9 + i];
			for(int i = 0;i < privateKey.length;++i) privateKey[i] = data[9 + publicKey.length + i];
			resMap.put("publicKey", new String(publicKey));
			resMap.put("privateKey", new String(privateKey));
			return resMap;
		}
		
		public static byte[] loginPack(String id, String password) {
	    	
			byte[] signInData = ("xxx" + id + password).getBytes(Charset.forName("UTF-8"));
			
			signInData[0] = 1;
			
			signInData[1] = (byte) id.getBytes(Charset.forName("UTF-8")).length;
			
			signInData[2] = (byte) password.getBytes(Charset.forName("UTF-8")).length;
			
			return signInData;
		}
		
		public static Map<String, String> loginUnPack(ByteBuffer loginPackage) {
			Map<String, String> resMap = new HashMap<>();
			byte[] data = loginPackage.array(), id = new byte[loginPackage.get(1)], password = new byte[loginPackage.get(2)];
			for(int i = 0;i < id.length;++i) id[i] = data[3 + i];
			for(int i = 0;i < password.length;++i) password[i] = data[3 + id.length + i];
			resMap.put("id", new String(id, Charset.forName("UTF-8")));
			resMap.put("password", new String(password, Charset.forName("UTF-8")));
			return resMap;
		}
	}
	
	public static class LoginUtils {
		
		public static String passwordComplie(String password) {
	        Random r = new Random();
	        StringBuilder sb = new StringBuilder(16);
	        sb.append(r.nextInt(99999999)).append(r.nextInt(99999999));
	        int len = sb.length();
	        if (len < 16) {
	            for (int i = 0; i < 16 - len; i++) {
	                sb.append("0");
	            }
	        }
	        String salt = sb.toString();
	        password = md5Hex(password + salt);
	        char[] cs = new char[48];
	        for (int i = 0; i < 48; i += 3) {
	            cs[i] = password.charAt(i / 3 * 2);
	            char c = salt.charAt(i / 3);
	            cs[i + 1] = c;
	            cs[i + 2] = password.charAt(i / 3 * 2 + 1);
	        }
	        return new String(cs);
	    }

	    public static boolean verifyPassword(String password, String md5) {
	        char[] cs1 = new char[32];
	        char[] cs2 = new char[16];
	        for (int i = 0; i < 48; i += 3) {
	            cs1[i / 3 * 2] = md5.charAt(i);
	            cs1[i / 3 * 2 + 1] = md5.charAt(i + 2);
	            cs2[i / 3] = md5.charAt(i + 1);
	        }
	        String salt = new String(cs2);
	        return md5Hex(password + salt).equals(new String(cs1));
	    }

	    public static String md5Hex(String src) {
	        try {
	            MessageDigest md5 = MessageDigest.getInstance("MD5");
	            byte[] bs = md5.digest(src.getBytes());
	            return new String(new Hex().encode(bs));
	        } catch (Exception e) {
	            return null;
	        }
	    }
	    
	}
	
	public static class Convertion {
		
		public static byte[] int2Bytes(int n)
		{
			
			  byte[] b = new byte[4];  
			  
			  b[3] = (byte) (n & 0xff);  
			  
			  b[2] = (byte) (n >> 8 & 0xff);  
			  
			  b[1] = (byte) (n >> 16 & 0xff);  
			  
			  b[0] = (byte) (n >> 24 & 0xff); 
			  
			  return b;  
		}
		
		
		public static int bytes2Int(byte[] bytes )
		{
			
		    int int1= bytes[3] & 0xff;
		    
		    int int2= (bytes[2] & 0xff) << 8;
		    
		    int int3= (bytes[1] & 0xff) << 16;
		    
		    int int4= (bytes[0] & 0xff) << 24;

		    return int1|int2|int3|int4;
		}
		
		public static byte[] BytesCapture(byte[] src,int offset,int length)
		{
			
			  byte[] result = new byte[length]; 
			  
			  for(int index = 0; index < length; index++) {
				  
				  try {
					  
				  result[index] = src[index + offset];
				  
				  } catch (ArrayIndexOutOfBoundsException e) {
					  
					  break;
					  
				  }
				  
			  }
			  
			  return result;  
			  
		}
		
		public static byte[] BytesExpand(int n,byte[] src)
		{
			
			  byte[] result = new byte[n]; 
			  
			  for(int index = 0; index < n; index++) {
				  
				  try {
					  
				  result[index] = src[index];
				  
				  } catch (ArrayIndexOutOfBoundsException e) {
					  
					  break;
					  
				  }
				  
			  }
			  
			  return result;  
			  
		}
	}
	
	public static class MD5Utils {
		public static MessageDigest messagedigest;
		
		static {
			try {
	            messagedigest = MessageDigest.getInstance("MD5");
	        } catch (NoSuchAlgorithmException e) {
	            e.printStackTrace();
	        }
		}
		
		public static byte[] MD5Byte(byte[] src) {
			return messagedigest.digest(src);
		}
	}
	
	public static class RSAUtils {
		public static final String CHARSET = "UTF-8";
	    public static final String RSA_ALGORITHM = "RSA";

	    public static Map<String, String> createKeys(int keySize) {

	        KeyPairGenerator kpg;
	        try {
	            kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
	        } catch (NoSuchAlgorithmException e) {
	            throw new IllegalArgumentException("No such algorithm-->[" + RSA_ALGORITHM + "]");
	        }

	        kpg.initialize(keySize);
	        KeyPair keyPair = kpg.generateKeyPair();
	        Key publicKey = keyPair.getPublic();
	        String publicKeyStr = Base64.encodeBase64URLSafeString(publicKey.getEncoded());
	        Key privateKey = keyPair.getPrivate();
	        String privateKeyStr = Base64.encodeBase64URLSafeString(privateKey.getEncoded());
	        
	        Map<String, String> keyPairMap = new HashMap<String, String>();
	        keyPairMap.put("publicKey", publicKeyStr);
	        keyPairMap.put("privateKey", privateKeyStr);

	        return keyPairMap;
	    }


	    public static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
	        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
	        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
	        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
	        return key;
	    }


	    public static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
	        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
	        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
	        RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
	        return key;
	    }

	    public static byte[] publicEncrypt(byte[] data, RSAPublicKey publicKey) {
	        try {
	            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	            return rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data, publicKey.getModulus().bitLength());
	        } catch (Exception e) {
	            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
	        }
	    }

	    public static byte[] privateDecrypt(byte[] data, RSAPrivateKey privateKey) {
	        try {
	            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	            cipher.init(Cipher.DECRYPT_MODE, privateKey);
	            return rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, data, privateKey.getModulus().bitLength());
	        } catch (Exception e) {
	            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
	        }
	    }

	    
	    public static byte[] privateEncrypt(byte[] data, RSAPrivateKey privateKey) {
	        try {
	            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
	            return rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data, privateKey.getModulus().bitLength());
	        } catch (Exception e) {
	            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
	        }
	    }

	    public static byte[] publicDecrypt(byte[] data, RSAPublicKey publicKey) {
	        try {
	            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	            cipher.init(Cipher.DECRYPT_MODE, publicKey);
	            return rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, data, publicKey.getModulus().bitLength());
	        } catch (Exception e) {
	            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
	        }
	    }

	    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) throws IOException {
	        int maxBlock = 0;
	        if (opmode == Cipher.DECRYPT_MODE) {
	            maxBlock = keySize / 8;
	        } else {
	            maxBlock = keySize / 8 - 11;
	        }
	        ByteArrayOutputStream out = new ByteArrayOutputStream();
	        int offSet = 0;
	        byte[] buff;
	        int i = 0;
	        try {
	            while (datas.length > offSet) {
	                if (datas.length - offSet > maxBlock) {
	                    buff = cipher.doFinal(datas, offSet, maxBlock);
	                } else {
	                    buff = cipher.doFinal(datas, offSet, datas.length - offSet);
	                }
	                out.write(buff, 0, buff.length);
	                i++;
	                offSet = i * maxBlock;
	            }
	        } catch (Exception e) {
	            throw new RuntimeException("加解密阀值为[" + maxBlock + "]的数据时发生异常", e);
	        }
	        byte[] resultDatas = out.toByteArray();
	        out.close();
	        return resultDatas;
	    }
	}
	
	public static class Base64Utils {
		
		public static ImageIcon base642Image(String base64) {
			byte[] btDataFile = Base64.decodeBase64(base64);
			BufferedImage image;
			try {
				image = ImageIO.read(new ByteArrayInputStream(btDataFile));
			} catch (IOException e) {
				e.printStackTrace();
				return null;
			}

			return new ImageIcon(image);
		}
		public static String readBase64(File file) throws IOException {
			byte[] fileByte = Files.readAllBytes(file.toPath());
			
			return  Base64.encodeBase64String(fileByte);
		}
	}
	
	public static void main(String[] args) {
		String passString = utils.LoginUtils.passwordComplie("China123");
		System.out.println(passString);

	}

}
