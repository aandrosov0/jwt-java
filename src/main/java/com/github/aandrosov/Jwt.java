package com.github.aandrosov;

import jdk.nashorn.internal.parser.JSONParser;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Jwt {

    private String alg = "none";
    private String typ;
    private String cty;

    private String iss;
    private String sub;
    private String aud;
    private String jti;

    private Long exp;
    private Long nbf;
    private Long iat;

    private final Map<String, Object> claims = new HashMap<>();

    private String signature;

    public Jwt() {

    }

    public Jwt(String jwt) {
        Base64.Decoder base64url = Base64.getUrlDecoder();

        String[] splitJwt = jwt.split("\\.", 3);

        String header = splitJwt.length > 0 ? splitJwt[0] : null;
        if(header == null) {
            throw new JwtElementNotFoundException("Invalid JWT. Can't find header");
        }

        parseHeader(header.getBytes(), base64url);

        String payload = splitJwt.length > 1 ? splitJwt[1] : null;
        if(payload == null) {
            throw new JwtElementNotFoundException("Invalid JWT. Can't find payload");
        }

        parsePayload(payload.getBytes(), base64url);

        signature = splitJwt.length == 3 ? new String(base64url.decode(splitJwt[2])) : null;
    }

    @Override
    public String toString() {
        System.out.println(getPayload());
        Base64.Encoder base64url = Base64.getUrlEncoder();
        String header64 = base64url.withoutPadding().encodeToString(getHeader().getBytes());
        String payload64 = base64url.withoutPadding().encodeToString(getPayload().getBytes());

        String signature64 = null;
        if(signature != null) {
            signature64 = base64url.withoutPadding().encodeToString(signature.getBytes());
        }

        return header64 + "." + payload64 + (signature64 == null ? "" : '.' + signature64);
    }

    public boolean verify(String key, String hmacAlgo) throws NoSuchAlgorithmException, InvalidKeyException {
        String tmpSignature = signature;
        signature = null;
        String cmpSignature = sign(toString(), key, hmacAlgo);
        signature = tmpSignature;

        return cmpSignature.equals(signature);
    }

    public void sign(String key, String hmacAlgo) throws NoSuchAlgorithmException, InvalidKeyException {
        signature = null;
        signature = sign(toString(), key, hmacAlgo);
    }

    public void addClaim(String key, Object value) {
        claims.put(key, value);
    }

    public Object getClaim(String key) {
        return claims.get(key);
    }

    public void removeClaim(String key) {
        claims.remove(key);
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getTyp() {
        return typ;
    }

    public void setTyp(String typ) {
        this.typ = typ;
    }

    public String getCty() {
        return cty;
    }

    public void setCty(String cty) {
        this.cty = cty;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(long exp) {
        this.exp = exp;
    }

    public Long getNbf() {
        return nbf;
    }

    public void setNbf(long nbf) {
        this.nbf = nbf;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(long iat) {
        this.iat = iat;
    }

    public String getHeader() {
        return "{\"alg\":\"" + alg + '"'
                + (typ == null || typ.isEmpty() ? "" : ",\"typ\":" + '"' + typ + '"')
                + (cty == null || cty.isEmpty() ? "" : ",\"cty\":" + '"' + cty + '"')
                + "}";
    }

    public String getPayload() {
        StringBuilder payload = new StringBuilder("{"
                + (iss == null || iss.isEmpty() ? "" : "\"iss\":\"" + iss + '"'));

        if(sub != null && !sub.isEmpty()) {
            payload.append(payload.length() > 1 ? ",\"sub\":\"" + sub : "\"sub\":\"" + sub).append('"');
        }

        if(aud != null && !aud.isEmpty()) {
            payload.append(payload.length() > 1 ? ",\"aud\":\"" + aud : "\"aud\":\"" + aud).append('"');
        }

        if(jti != null && !jti.isEmpty()) {
            payload.append(payload.length() > 1 ? ",\"jti\":\"" + jti : "\"jti\":\"" + jti).append('"');
        }

        if(exp != null) {
            payload.append(payload.length() > 1 ? ",\"exp\":" + exp : "\"exp\":" + exp);
        }

        if(nbf != null) {
            payload.append(payload.length() > 1 ? ",\"nbf\":" + nbf : "\"nbf\":" + nbf);
        }

        if(iat != null) {
            payload.append(payload.length() > 1 ? ",\"iat\":" + iat : "\"nbf\":" + iat);
        }

        for(Map.Entry<String, Object> claim : claims.entrySet()) {
            payload.append(payload.length() > 1 ? "," + claimToJsonValue(claim) : claimToJsonValue(claim));
        }

        return payload + "}";
    }

    private static String claimToJsonValue(Map.Entry<?, ?> claim) {
        Object value = claim.getValue();

        if(value instanceof Map) {
            return "\"" + claim.getKey() + "\":" + new JSONObject((Map<?, ?>) value);
        }

        if(value instanceof Collection) {
            return "\"" + claim.getKey() + "\":" + JSONArray.toJSONString(Arrays.asList(((Collection<?>) value).toArray()));
        }

        if(value.getClass().isArray()) {
            return "\"" + claim.getKey() + "\":" + JSONArray.toJSONString(Arrays.asList((Object[]) value));
        }

        return "\"" + claim.getKey() + "\":" + quoteIfString(value);
    }

    private static String sign(String data, String key, String hmacAlgo) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), hmacAlgo);
        Mac mac = Mac.getInstance(hmacAlgo);
        mac.init(secretKeySpec);
        return new String(data.getBytes());
    }

    private static String quoteIfString(Object object) {
        if(object instanceof String) {
            return JSONParser.quote(String.valueOf(object));
        }

        return String.valueOf(object);
    }

    private void parseHeader(byte[] header, Base64.Decoder urlDecoder) {
        JSONObject jsonObject = (JSONObject) JSONValue.parse(new String(urlDecoder.decode(header)));

        alg = (String) jsonObject.get("alg");
        if(alg == null) {
            throw new JwtMandatoryFieldNotFound("Invalid header. Can't find alg value");
        }

        typ = (String) jsonObject.get("typ");
        cty = (String) jsonObject.get("cty");
    }

    private void parsePayload(byte[] payload, Base64.Decoder urlDecoder) {
        JSONObject jsonObject = (JSONObject) JSONValue.parse(new String(urlDecoder.decode(payload)));
        iss = (String) jsonObject.get("iss");
        sub = (String) jsonObject.get("sub");
        aud = (String) jsonObject.get("aud");
        jti = (String) jsonObject.get("jti");
        exp = (Long) jsonObject.get("exp");
        nbf = (Long) jsonObject.get("nbf");
        iat = (Long) jsonObject.get("iat");

        Set<?> set = jsonObject.entrySet();
        for(Object object : set.toArray()) {
            Map.Entry<?, ?> entry = (Map.Entry<?, ?>) object;

            if(!Arrays.asList("iss", "sub", "aud", "jti", "exp", "nbf", "iat").contains((String) entry.getKey())) {
                claims.put((String) entry.getKey(), entry.getValue());
            }
        }
    }
}
