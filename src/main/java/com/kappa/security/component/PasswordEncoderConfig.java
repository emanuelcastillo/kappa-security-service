package com.kappa.security.component;

//nuestro propio encoder
//@Component
public class PasswordEncoderConfig /*implements PasswordEncoder*/ {

    public String encode(CharSequence rawPassword) {
        return String.valueOf(rawPassword.toString().hashCode());
    }

    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        var passwordString =  String.valueOf(rawPassword.toString().hashCode());
        return encodedPassword.equals(passwordString);
    }

    public boolean upgradeEncoding(String encodedPassword) {
        return false;//PasswordEncoder.super.upgradeEncoding(encodedPassword);
    }
}
