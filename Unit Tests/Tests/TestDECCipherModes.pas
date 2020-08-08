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

{$M+} // DUnitX would add it anyway
unit TestDECCipherModes;

interface

// Needs to be included before any other statements
{$I defines.inc}

uses
  {$IFNDEF DUnitX}
  TestFramework,
  {$ENDIF}
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ENDIF}
  DECCipherBase, DECCipherModes, DECCIpherFormats, System.SysUtils;

type
  /// <summary>
  ///   Class for opening up TDECPaddedCiphers so that the individual padding
  ///   methods can be tested.
  /// </summary>
  TTestableCipherModes = class(TDECCipherModes)
  strict protected
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    /// <summary>
    ///   Electronic Code Book
    ///   Mode cmECBx needs message padding to be a multiple of Cipher.BlockSize
    ///   and should be used only in 1-byte Streamciphers.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure EncodeECBx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   8bit Output Feedback mode, needs no padding
    /// </summary>
    procedure EncodeOFB8(Source, Dest: PByteArray; Size: Integer);  override;
    /// <summary>
    ///   8bit Cipher Feedback mode, needs no padding and works on 8 bit
    ///   Feedback Shift Registers.
    /// </summary>
    procedure EncodeCFB8(Source, Dest: PByteArray; Size: Integer);  override;
    /// <summary>
    ///   8Bit CFS, double Cipher Feedback mode (CFB), needs no padding and
    ///   works on 8 bit Feedback Shift Registers.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure EncodeCFS8(Source, Dest: PByteArray; Size: Integer);  override;
    /// <summary>
    ///   Cipher Feedback mode (CFB) on Blocksize of Cipher, needs no padding
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure EncodeCFBx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   Output Feedback mode on Blocksize of Cipher, needs no padding and
    ///   works on 8 bit Feedback Shift Registers.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure EncodeOFBx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   double Cipher Feedback mode (CFB) on Blocksize of Cipher, needs no padding.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure EncodeCFSx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   Cipher Block Chaining, with CFB8 padding of truncated final block
    ///   It needs no external padding, because internally the last
    ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these Modes
    ///   cannot be used to process any more data. If needed to process chunks of
    ///   data then each chunk must be algined to Cipher.BufferSize bytes.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure EncodeCBCx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   double CBC, with CFS8 padding of truncated final block
    ///   It needs no external padding, because internally the last
    ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these Modes
    ///   cannot be used to process any more data. If needed to process chunks of
    ///   data then each chunk must be algined to Cipher.BufferSize bytes.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure EncodeCTSx(Source, Dest: PByteArray; Size: Integer); override;
    {$IFDEF DEC3_CMCTS}
    /// <summary>
    ///   double CBC, with
    ///   for DEC 3.0 compatibility only
    ///   This is a proprietary mode developed by Frederik Winkelsdorf. It
    ///   replaces the CFS8 padding of the truncated final block with a CFSx padding.
    ///   Useful when converting projects that previously used the old DEC v3.0. It
    ///   has the same restrictions for external padding and chunk processing as
    ///   cmCTSx has. It has a less secure padding of the truncated final block.
    ///   (to enable it see DECOptions.inc)
    /// </summary>
    procedure EncodeCTS3(Source, Dest: PByteArray; Size: Integer); override;
    {$ENDIF}
    /// <summary>
    ///   Electronic Code Book
    ///   Mode cmECBx needs message padding to be a multiple of Cipher.BlockSize
    ///   and should be used only in 1-byte Streamciphers.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure DecodeECBx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   8bit Output Feedback mode, needs no padding
    /// </summary>
    procedure DecodeOFB8(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   8bit Cipher Feedback mode, needs no padding and works on 8 bit
    ///   Feedback Shift Registers.
    /// </summary>
    procedure DecodeCFB8(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   8Bit CFS, double Cipher Feedback mode (CFB), needs no padding and
    ///   works on 8 bit Feedback Shift Registers.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure DecodeCFS8(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   Cipher Feedback mode (CFB) on Blocksize of Cipher, needs no padding
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure DecodeCFBx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   Output Feedback mode on Blocksize of Cipher, needs no padding and
    ///   works on 8 bit Feedback Shift Registers.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure DecodeOFBx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   double Cipher Feedback mode (CFB) on Blocksize of Cipher, needs no padding.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure DecodeCFSx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   Cipher Block Chaining, with CFB8 padding of truncated final block
    ///   It needs no external padding, because internally the last
    ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these Modes
    ///   cannot be used to process any more data. If needed to process chunks of
    ///   data then each chunk must be algined to Cipher.BufferSize bytes.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    /// </summary>
    procedure DecodeCBCx(Source, Dest: PByteArray; Size: Integer); override;
    /// <summary>
    ///   double CBC, with CFS8 padding of truncated final block
    ///   It needs no external padding, because internally the last
    ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these Modes
    ///   cannot be used to process any more data. If needed to process chunks of
    ///   data then each chunk must be algined to Cipher.BufferSize bytes.
    ///   This one works on Blocks of Cipher.BufferSize bytes, when using a
    ///   Blockcipher that's equal to Cipher.BlockSize.
    ///   This one is a proprietary mode developed by Hagen Reddmann. This mode
    ///   works as cmCBCx, cmCFBx, cmCFB8 but with double XOR'ing of the
    ///   inputstream into Feedback register.
    /// </summary>
    procedure DecodeCTSx(Source, Dest: PByteArray; Size: Integer); override;
    {$IFDEF DEC3_CMCTS}
    /// <summary>
    ///   double CBC, with
    ///   for DEC 3.0 compatibility only
    ///   This is a proprietary mode developed by Frederik Winkelsdorf. It
    ///   replaces the CFS8 padding of the truncated final block with a CFSx padding.
    ///   Useful when converting projects that previously used the old DEC v3.0. It
    ///   has the same restrictions for external padding and chunk processing as
    ///   cmCTSx has. It has a less secure padding of the truncated final block.
    ///   (to enable it see DECOptions.inc)
    /// </summary>
    procedure DecodeCTS3(Source, Dest: PByteArray; Size: Integer); override;
    {$ENDIF}
    /// <summary>
    ///   An initialized context needs to be present, because it is being used
    ///   initially (at least partily)
    /// </summary>
    class function Context: TCipherContext; override;
  end;

  TFormattedCipherClass = class of TDECFormattedCipher;

  /// <summary>
  ///   One entry in a list of tests
  /// </summary>
  TTestEntry = record
    /// <summary>
    ///   Input value, needs to be of block size length or a multiple of it
    /// </summary>
    Input      : RawByteString;
    /// <summary>
    ///   Expected output value, needs to be of block size length or a multiple of it
    /// </summary>
    Output     : RawByteString;
    /// <summary>
    ///   Expected output value which is used if Output is empty. Contains the
    ///   output in hexadecimal notation.
    /// </summary>
    OutputHex  : RawByteString;
    /// <summary>
    ///   Init Vektor für den ersten Test
    /// </summary>
    InitVector : RawByteString;
    /// <summary>
    ///   Class reference for the cipher class used for this test.
    /// </summary>
    TestClass  : TFormattedCipherClass;
    /// <summary>
    ///   Block concatenating/padding mode
    /// </summary>
    Mode       : TCipherMode;
  end;

  /// <summary>
  ///   Prototype for a function to be passed to the generic test method
  /// </summary>
  TTestFunction = procedure(Source, Dest: PByteArray; Size: Integer) of object;

  /// <summary>
  ///   Defines what is being tested: Encryption or decryption
  /// </summary>
  TTestDirection = (dEncode, dDecode);

  /// <summary>
  ///   Testmethoden für Klasse TDECCipherModes
  /// </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipherModes = class(TTestCase)
  strict private
    FDECPaddedCipher: TTestableCipherModes;
  private
    procedure DoTest(Data: array of TTestEntry; TestFunction: TTestFunction);
    /// <summary>
    ///   Carries out the actual test
    /// </summary>
    /// <param name="Data">
    ///   Array with the data definint inputs and outputs for the tests
    /// </param>
    /// <param name="Direction">
    ///   dEncode for Encode/Encrypt, dDecode for Decode/Decrypt
    /// </param>
    procedure DoTestNew(Data: array of TTestEntry; Direction:TTestDirection);
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeECBx;
    procedure TestEncodeOFB8;
    procedure TestEncodeCFB8;
    procedure TestEncodeCFS8;
    procedure TestEncodeCFBx;
    procedure TestEncodeOFBx;
    procedure TestEncodeCFSx;
    procedure TestEncodeCBCx;
    procedure TestEncodeCTSx;
    procedure TestDecodeECBx;
    procedure TestDecodeOFB8;
    procedure TestDecodeCFB8;
    procedure TestDecodeCFS8;
    procedure TestDecodeCFBx;
    procedure TestDecodeOFBx;
    procedure TestDecodeCFSx;
    procedure TestDecodeCBCx;
    procedure TestDecodeCTSx;
    procedure TestEncode;
    procedure TestDecode;
  end;

implementation

uses
  DECCiphers, DECUtil;

procedure TestTDECCipherModes.SetUp;
begin
  FDECPaddedCipher := TTestableCipherModes.Create;
end;

procedure TestTDECCipherModes.TearDown;
begin
  FDECPaddedCipher.Free;
  FDECPaddedCipher := nil;
end;

procedure TestTDECCipherModes.DoTest(Data: array of TTestEntry; TestFunction:TTestFunction);
var
  Dest   : TByteArray;
  Source : TByteArray;
  i, n   : Integer;
  Result : string;
begin
  for i := Low(Data) to High(Data) do
  begin
    FDECPaddedCipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf(Data[i].InitVector), $FF);

    FillChar(Source[0], Length(Source), $FF);
    FillChar(Dest[0],   Length(Dest),   $FF);


    Move(Data[i].Input[1], Source[0], Length(Data[i].Input));

    TestFunction(@Source, @Dest, Length(Data[i].Input));

    // Output is noted non hexadecimal
    if Data[i].Output <> '' then
    begin
      for n := Low(Dest) to Length(Data[i].Output)-1 do
      begin
        CheckEquals(Ord(Data[i].Output[n+1]), Dest[n],
                    IntToStr(n+1) + '. position is wrong. ' +
                    IntToStr(i) + '. test series');
      end;
    end
    else
    begin
      // Output is noted in hex
      Result := '';
      for n := Low(Dest) to (Length(Data[i].OutputHex) div 2)-1 do
        Result := Result + IntToHex(Dest[n], 2);

      CheckEquals(string(Data[i].OutputHex), Result,
                  'Data is wrong. ' + IntToStr(i) + '. test series');
    end;
  end;
end;

procedure TestTDECCipherModes.DoTestNew(Data: array of TTestEntry; Direction:TTestDirection);
var
  Dest   : TBytes;
  Source : TBytes;
  i, n   : Integer;
  Result : string;

  Cipher : TDECFormattedCipher;
begin
  for i := Low(Data) to High(Data) do
  begin
    Cipher := Data[i].TestClass.Create;
    Cipher.Mode := Data[i].Mode;

    try
//      if Cipher.ClassType <> TCipher_Null then
        Cipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf(Data[i].InitVector), $FF);
//      else
//        Cipher.Init(BytesOf(RawByteString('')), BytesOf(Data[i].InitVector), $FF);

      SetLength(Source, length(Data[i].Input));
      FillChar(Source[0], Length(Source), $FF);

      Move(Data[i].Input[1], Source[0], Length(Data[i].Input));

      if (Direction = dEncode) then
        Dest := Cipher.EncodeBytes(Source)
      else
        Dest := Cipher.DecodeBytes(Source);

      // Output is noted non hexadecimal
      if Data[i].Output <> '' then
      begin
        for n := Low(Dest) to High(Dest) do
        begin
          CheckEquals(Ord(Data[i].Output[n+1]), Dest[n],
                      IntToStr(n+1) + '. position is wrong. ' +
                      IntToStr(i) + '. test series. Expected: ' +
                      Data[i].Output + ' was: ' + DECUtil.BytesToRawString(Dest));
        end;
      end
      else
      begin
        // Output is noted in hex
        Result := '';
        for n := Low(Dest) to High(Dest) do
          Result := Result + IntToHex(Dest[n], 2);

        for n := Low(Result) to High(Result) do
          CheckEquals(Data[i].OutputHex[n], Result[n],
                      IntToStr(n+1) + '. position is wrong. ' +
                      IntToStr(i) + '. test series. Expected: ' +
                      Data[i].OutputHex + ' was: ' + Result);
      end;

    finally
      Cipher.Free;
    end;
  end;
end;

procedure TestTDECCipherModes.TestEncodeECBx;
const
  Data: array[1..3] of TTestEntry = ((Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:    'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      TestClass: TCipher_Null;
                                      Mode:      TCipherMode.cmECBx),
                                     (Input:     '000000000000000000000000';
                                      Output:    '000000000000000000000000';
                                      TestClass: TCipher_Null;
                                      Mode:      TCipherMode.cmECBx),
                                     (Input:     '12345678';
                                      Output:    '12345678';
                                      TestClass: TCipher_Null;
                                      Mode:      TCipherMode.cmECBx));
begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestEncodeOFB8;
const
  Data: array[1..3] of TTestEntry = ((Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:    '';
                                      OutputHex: 'FE5A89A7A1F4BD29DFFADFCF2239E1F581106DA64C0AE704';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmOFB8),
                                     (Input:     '000000000000000000000000';
                                      Output:    '';
                                      OutputHex: '8F28FAD3D482CA51A680A4B35F479E95E0720EC2296C806C';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmOFB8),
                                     (Input:     '12345678';
                                      Output:    '';
                                      OutputHex: '8E2AF9D7D184CD59';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmOFB8));
begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestEncodeCFB8;
const
  Data: array[1..3] of TTestEntry = ((Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:    '';
                                      OutputHex: 'FE604D3DF9C2AE3D7839AF5BDEE8FD9078544A1996EC4F1C';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFB8),
                                     (Input:     '000000000000000000000000';
                                      Output:    '';
                                      OutputHex: '8FD637FC449CF89F1E5EEBB66BED15C7F8C63B4481F74C5A';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFB8),
                                     (Input:     '12345678';
                                      Output:    '';
                                      OutputHex: '8EF08D6414063543';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFB8));
begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestEncodeCFS8;
const
  Data: array[1..3] of TTestEntry = ((Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:    '';
                                      OutputHex: 'FEAB3839BBA059FC1FECBF798CEF537803F10F15967E3ABD';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFS8),
                                     (Input:     '000000000000000000000000';
                                      Output:    '';
                                      OutputHex: '8F9661B53B06D611BA916562F4420DA4B6EFD550BF01DA2C';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFS8),
                                     (Input:     '12345678';
                                      Output:    '';
                                      OutputHex: '8EEA2F2F86159953';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFS8));
begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestEncodeCFBx;
const
  Data: array[1..3] of TTestEntry = ((Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:    '';
                                      OutputHex: 'FED41297FD52669BF5361295F3BD937EF0644802ED92DC21';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFBx),
                                     (Input:     '000000000000000000000000';
                                      Output:    '';
                                      OutputHex: '8FA661E3882411E35337C15BAE99B7CBDD988AC4FABB3368';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFBx),
                                     (Input:     '12345678';
                                      Output:    '';
                                      OutputHex: '8EA462E78D2216EB';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFBx));
begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestEncodeOFBx;
const
  Data: array[1..3] of TTestEntry = ((Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:    '';
                                      OutputHex: 'FED41297FD52669B4221F913AF978D77292C958B2A9E289A';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmOFBx),
                                     (Input:     '000000000000000000000000';
                                      Output:    '';
                                      OutputHex: '8FA661E3882411E33B5B826FD2E9F217484EF6EF4FF84FF2';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmOFBx),
                                     (Input:     '12345678';
                                      Output:    '';
                                      OutputHex: '8EA462E78D2216EB';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmOFBx));
begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestEncodeCFSx;
const
  Data: array[1..3] of TTestEntry = ((Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:    '';
                                      OutputHex: 'FED41297FD52669B0DEC818A383ADA358E469BE634B7AFBC';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFSx),
                                     (Input:     '000000000000000000000000';
                                      Output:    '';
                                      OutputHex: '8FA661E3882411E3DB7258A29424D11F2BB6B4607D24D5DB';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFSx),
                                     (Input:     '12345678';
                                      Output:    '';
                                      OutputHex: '8EA462E78D2216EB';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCFSx));
begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestEncodeCBCx;
const
  Data: array[1..3] of TTestEntry = ((Input     : 'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output    : 'qsqwqsq'+#$7f+'89:;<=>/ikioikiw';
                                      InitVector: '01234567';
                                      TestClass : TCipher_NULL;
                                      Mode      : TCipherMode.cmCBCx),
                                     (Input     : '000000000000000000000000';
                                      Output    : '00000000' + #0#0#0#0#0#0#0#0 + '00000000';
                                      InitVector: #0#0#0#0#0#0#0#0;
                                      TestClass : TCipher_NULL;
                                      Mode      : TCipherMode.cmCBCx),
                                     (Input     : '000000000000000000000000';
                                      Output    : #0#1#2#3#4#5#6#7 + '01234567' + #0#1#2#3#4#5#6#7;
                                      InitVector: '01234567';
                                      TestClass : TCipher_NULL;
                                      Mode      : TCipherMode.cmCBCx));

begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestEncodeCTSx;
const
  Data: array[1..3] of TTestEntry = ((Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:    '';
                                      OutputHex: 'FD73DA2F279926A19A65EFA8EBA5EEB67A778C6CD73294F5';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCTSx),
                                     (Input:     '000000000000000000000000';
                                      Output:    '';
                                      OutputHex: '1D538CCCF38138A6BD4655272CC67443A0E32865EB422745';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCTSx),
                                     (Input:     '12345678';
                                      Output:    '';
                                      OutputHex: '8EE274B893296F9E';
                                      TestClass: TCipher_1DES;
                                      Mode:      TCipherMode.cmCTSx));
begin
  DoTestNew(Data, dEncode);
end;

procedure TestTDECCipherModes.TestDecodeECBx;
var
  Dest   : TByteArray;
  Source : TByteArray;
const
  Data: array[1..3] of TTestEntry = ((Input:      'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      TestClass : TCipher_NULL),
                                     (Input:      '000000000000000000000000';
                                      Output:     '000000000000000000000000';
                                      TestClass : TCipher_NULL),
                                     (Input:      '12345678';
                                      Output:     '12345678';
                                      TestClass : TCipher_NULL));
begin
  DoTest(Data, FDECPaddedCipher.DecodeECBx);
end;

procedure TestTDECCipherModes.TestDecodeOFB8;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.DecodeOFB8(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestDecodeCFB8;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.DecodeCFB8(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestDecodeCFS8;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.DecodeCFS8(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestDecodeCFBx;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.DecodeCFBx(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestDecodeOFBx;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.DecodeOFBx(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestDecodeCFSx;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.DecodeCFSx(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestDecodeCBCx;
const
  Data: array[1..3] of TTestEntry = ((Input     : 'qsqwqsq'+#$7f+'89:;<=>/ikioikiw';
                                      Output    : 'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      InitVector: '01234567';
                                      TestClass : TCipher_NULL),
                                     (Input     : '00000000' + #0#0#0#0#0#0#0#0 + '00000000';
                                      Output    : '000000000000000000000000';
                                      InitVector: #0#0#0#0#0#0#0#0;
                                      TestClass : TCipher_NULL),
                                     (Input     : #0#1#2#3#4#5#6#7 + '01234567' + #0#1#2#3#4#5#6#7;
                                      Output    : '000000000000000000000000';
                                      InitVector: '01234567';
                                      TestClass : TCipher_NULL));

begin
  DoTest(Data, FDECPaddedCipher.DecodeCBCx);
end;

procedure TestTDECCipherModes.TestDecodeCTSx;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.DecodeCTSx(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestEncode;
var
  DataSize: Integer;
  Dest: TObject;
  Source: TObject;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.Encode(Source, Dest, DataSize);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestDecode;
var
  DataSize: Integer;
  Dest: TObject;
  Source: TObject;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.Decode(Source, Dest, DataSize);
  // TODO: Methodenergebnisse prüfen
end;

{ TTestableCipherPaddings }

procedure TTestableCipherModes.DecodeCBCx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DecodeCFB8(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DecodeCFBx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DecodeCFS8(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DecodeCFSx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DecodeCTSx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DecodeECBx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DecodeOFB8(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DecodeOFBx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.DoDecode(Source, Dest: Pointer;
  Size: Integer);
begin
  // Simple copying of the data on purpose to be able to test the paddings
  // without requiring a cipher algorithm implementation
  Move(Source^, Dest^, Size);
end;

procedure TTestableCipherModes.DoEncode(Source, Dest: Pointer;
  Size: Integer);
begin
  // Simple copying of the data on purpose to be able to test the paddings
  // without requiring a cipher algorithm implementation
  Move(Source^, Dest^, Size);
end;

procedure TTestableCipherModes.DoInit(const Key; Size: Integer);
begin
{ TODO : Check if empty implementation is correct }
  // Empty on purpose as this method is not being called in any test but
  // is declared as virtual abstract in the base class. Implemented to suppress
  // any compiler messages about creating an instance containing abstract methods.
end;

class function TTestableCipherModes.Context: TCipherContext;
begin
  Result.BlockSize := 8;

  // Unused settings. Thus dummy initialization done
  Result.KeySize    := 56;
  Result.BufferSize := 8;
  Result.UserSize   := 1;
  Result.UserSave   := False;
end;

procedure TTestableCipherModes.EncodeCBCx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.EncodeCFB8(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.EncodeCFBx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.EncodeCFS8(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.EncodeCFSx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.EncodeCTSx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.EncodeECBx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.EncodeOFB8(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

procedure TTestableCipherModes.EncodeOFBx(Source, Dest: PByteArray;
  Size: Integer);
begin
  inherited;
end;

initialization
  // Register all test cases to be run
  {$IFNDEF DUnitX}
  RegisterTest(TestTDECCipherModes.Suite);
  {$ELSE}
// Currently not registered because it throws errors about abstract methods
//  TDUnitX.RegisterTestFixture(TestTDECCipherModes);
  {$ENDIF}
end.

