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
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends ActionBarActivity {
	private final String TAG = "MainActivity";
	TextView powerLevel;
	
	private RSAKeyPair keyPair;
	private final int keyLength = 1024;
	
    private final String transformation = "RSA/ECB/PKCS1Padding";
    private final String encoding = "UTF-8";
    
    private Cipher cipher;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
			keyPair = new RSAKeyPair(keyLength);
		} catch (GeneralSecurityException e) {
			Log.e(TAG, "Failed to create key pair");
		}
        Spinner spinner = (Spinner) findViewById(R.id.spinner);
// Create an ArrayAdapter using the string array and a default spinner layout
        ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(this,
                R.array.algorithms, android.R.layout.simple_spinner_item);
// Specify the layout to use when the list of choices appears
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
// Apply the adapter to the spinner
        spinner.setAdapter(adapter);
        spinner.setOnItemSelectedListener(new OnItemSelectedListener() {
  
			@Override
			public void onItemSelected(AdapterView<?> parent, View view,
					int pos, long id) {
				String selected = parent.getItemAtPosition(pos).toString();
				try{
					if (selected.equals("AES")){
						cipher = new AESCipher();
					}
					else if(selected.equals("RSA")){
						cipher = new RSACipher(keyPair.getPublicKey(), keyPair.getPrivateKey());
					}
				}catch(Exception e){
					Log.e(TAG, "Failed to create " + selected + " cipher");
				}
			}

			@Override
			public void onNothingSelected(AdapterView<?> parent) {
				// TODO Apéndice de método generado automáticamente
				
			}
        	 
        	});
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        Button b = (Button) findViewById(R.id.encryptButton);
        b.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {
				EditText rawTextContainer = (EditText) findViewById(R.id.rawText);
				String rawText = rawTextContainer.getText().toString();
				String encryptedText = "Encryption Failed";
				try {
					encryptedText = cipher.encrypt(rawText);
				} catch (Exception e) {
					Log.d(TAG, "Encryption Failed");
				}
				TextView encryptedTextView = (TextView) findViewById(R.id.encryptedText);
				encryptedTextView.setText(encryptedText);
				try {
					Log.d(TAG, "Decripted: " + cipher.decrypt(encryptedText));
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
