{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory of
  this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

/// <summary>
///   Demonstration of using a DEC cipher where the key security is improved by
///   using a key deviation function based on a hash algorithm.
/// </summary>
program Cipher_Console_KDF;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  DECCipherBase,
  DECCipherModes,
  DECCipherFormats,
  DECCiphers,
  DECHash;

var
  Cipher     : TCipher_TwoFish;
  // We use raw byte string here since Unicode handling of Windows console
  // is not given
  SourceText : RawByteString;
  CipherKey  : RawByteString; // Key for the initialization of our encryption run
  Seed       : RawByteString; // Seed for the key deviation function
  IV         : RawByteString; // Initialization vector for the en/decryption
  Input,
  Output     : TBytes;
  KeyKDF     : TBytes; // Key after applying KDF to it
  i          : Integer;
begin
  Cipher := TCipher_TwoFish.Create;

  try
    try
      WriteLn('Encryption demo using a KDF to improve key security');
      WriteLn;

      // Init our encryption, note that this is the German spelling of Password
      CipherKey := 'Passwort';
      Seed      := 'SaltValueForThePassword';

      KeyKDF := THash_SHA256.KDF1(BytesOf(CipherKey), BytesOf(Seed), 8);

      // The IV should be different each time you encrypt/decrypt something. The
      // decrypting party needs to know the IV as well of course.
      IV := #0#0#0#0#0#0#0#0;
      Cipher.Init(RawByteString(StringOf(KeyKDF)), IV, 0);
      Cipher.Mode := cmCBCx;

      SourceText := 'Beispielklartext';
      WriteLn('Source text: ' + SourceText);
      Input := System.SysUtils.BytesOf(SourceText);

      // Encrypt
      Output := Cipher.EncodeBytes(Input);
      // clean up inside the cipher instance, which also removes the key from RAM
      Cipher.Done;

      Write('Encrypted data in hex: ');
      for i := 0 to high(Output) do
        Write(IntToHex(Output[i], 2), ' ');

      WriteLn;

      // Decrypt
      Cipher.Init(RawByteString(StringOf(KeyKDF)), IV, 0);
      Output := Cipher.DecodeBytes(Output);
      // clean up inside the cipher instance, which also removes the key from RAM
      Cipher.Done;

      SourceText := RawByteString(System.SysUtils.StringOf(Output));

      WriteLn('Decrypted data: ' + SourceText);
    except
      on E: Exception do
        Writeln(E.ClassName, ': ', E.Message);
    end;

    ReadLn;
  finally
    Cipher.Free;
  end;
end.
