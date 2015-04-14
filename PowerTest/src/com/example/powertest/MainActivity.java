package com.example.powertest;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import android.content.Context;
import android.os.BatteryManager;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends ActionBarActivity {
	private final String TAG = "MainActivity";
	TextView powerLevel;
	
	private RSAKeyPair keyPair;
	private final int keyLength = 1024;
	
    private final String transformation = "RSA/ECB/PKCS1Padding";
    private final String encoding = "UTF-8";
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
			keyPair = new RSAKeyPair(keyLength);
		} catch (GeneralSecurityException e) {
			Log.e(TAG, "Failed to create key pair");
		}
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        Button b = (Button) findViewById(R.id.encryptButton);
        b.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {
				RSACipher cipher = new RSACipher();
				EditText rawTextContainer = (EditText) findViewById(R.id.rawText);
				String rawText = rawTextContainer.getText().toString();
				String encryptedText = "Encryption Failed";
				try {
					encryptedText = cipher.encrypt(rawText, keyPair.getPublicKey(), transformation, encoding);
				} catch (Exception e) {
					Log.d(TAG, "Encryption Failed");
				}
				TextView encryptedTextView = (TextView) findViewById(R.id.encryptedText);
				encryptedTextView.setText(encryptedText);
				try {
					Log.d(TAG, "Decripted: " + cipher.decrypt(encryptedText, keyPair.getPrivateKey(), transformation, encoding));
				} catch (Exception e) {
					Log.d(TAG, "Failed to decrypt");
				}
			}
		});
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
