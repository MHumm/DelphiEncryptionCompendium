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
unit TestDECCipherModesCCM;

interface

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}

uses
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  System.SysUtils,
  Generics.Collections,
  System.Math,
  DECBaseClass,
  DECCipherBase,
  DECCipherModes,
  DECCipherFormats,
  DECCiphers,
  AuthenticatedCiphersCommonTestData;

type
  // Testmethods for class TDECCipher
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCCM = class(TTestCase)
  strict private
    FTestDataList  : TAuthenticatedTestDataList;
    FCipherAES     : TCipher_AES;
    FTestBitLength : Integer; // AuthenticationBitLength for test for wring lengths
  private
    function IsEqual(const a, b: TBytes): Boolean;
    procedure DoTestEncodeStream_LoadAndTestCAVSData(const aMaxChunkSize: Int64);
    procedure DoTestEncodeStream_TestSingleSet(const aSetIndex, aDataIndex:
        Integer; const aMaxChunkSize: Int64 = -1);
    procedure DoTestInitFailureIVTooLong;
    procedure DoTestInitFailureIVTooShort;
    procedure DoTestRFC3610(EncodeTest: Boolean);
    procedure DoTestAuthenticationBitLengthWrong;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncode;
    /// <summary>
    ///   Uses testvectors from RFC 3610 but in a generated way
    ///   as they are specified like this.
    /// </summary>
    procedure TestEncodeRFC3610;
    /// <summary>
    ///   Uses testvectors from RFC 3610 but in a generated way
    ///   as they are specified like this.
    /// </summary>
    procedure TestDecodeRFC3610;
    procedure TestDecode;
    procedure TestDecodeStream;
    procedure TestInitIV;
    procedure TestInitFailureIVTooLong;
    procedure TestInitFailureIVTooShort;
    procedure TestEncodeStream;
    // Deferred: multi-call CCM streams (AEAD roadmap)
    procedure TestGetDataToAuthenticate;
    procedure TestSetDataToAuthenticate;
    procedure TestSetAuthenticationBitLengths;
    procedure TestSetWrongAuthenticationBitLengths;
    procedure TestGetStandardAuthenticationTagBitLengths;
    procedure TestGetExpectedAuthenticationResult;
    procedure TestSetExpectedAuthenticationResult;
  end;


implementation

uses
  System.Classes,
  DECTypes,
  DECFormat,
  DECUtil,
  DECAuthenticatedCipherModesBase;

{ TestTDECCCM }

procedure TestTDECCCM.SetUp;
var
  TestDataSet : TAuthenticatedCipherTestSetEntry;
begin
  inherited;

  FTestDataList   := TAuthenticatedTestDataList.Create;

  FCipherAES      := TCipher_AES.Create;
  FCipherAES.Mode := TCipherMode.cmCCM;

  TestDataSet.Keylen   := 256;
  TestDataSet.IVlen    := 92;
  TestDataSet.PTlen    := 23 * 8;
  TestDataSet.AADlen   := 64; // hdr1 length in initial source
  TestDataSet.Taglen   := 64; // authentication tag length in bit
  SetLength(TestDataSet.TestData, 2);
  TestDataSet.TestData[0].CryptKey    := 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf';
  TestDataSet.TestData[0].InitVector  := '00000003020100a0a1a2a3a4a5';
  TestDataSet.TestData[0].PT          := '08090a0b0c0d0e0f101112131415161718191a1b1c1d1e';
  TestDataSet.TestData[0].AAD         := '0001020304050607'; // hdr1 in initial source
  TestDataSet.TestData[0].CT          := '588c979a61c663d2f066d0c2c0f989806d5f6b61dac384';
  TestDataSet.TestData[0].TagResult   := '17e8d12cfdf926e0';
  TestDataSet.TestData[0].ModifiedAAD := '';
  TestDataSet.TestData[0].ModifiedCT  := '';

  TestDataSet.TestData[1].CryptKey    := 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf';
  TestDataSet.TestData[1].InitVector  := '00000006050403a0a1a2a3a4a5';
  TestDataSet.TestData[1].PT          := '0c0d0e0f101112131415161718191a1b1c1d1e';
  TestDataSet.TestData[1].AAD         := '000102030405060708090a0b'; // hdr1 in initial source
  TestDataSet.TestData[1].CT          := 'a28c6865939a9a79faaa5c4c2a9d4a91cdac8c';
  TestDataSet.TestData[1].TagResult   := '96c861b9c9e61ef1';
  TestDataSet.TestData[1].ModifiedAAD := '';
  TestDataSet.TestData[1].ModifiedCT  := '';

  FTestDataList.Add(TestDataSet);

  TestDataSet.Taglen   := 32; // authentication tag length in bit
  SetLength(TestDataSet.TestData, 1);
  TestDataSet.TestData[0].CryptKey    := '404142434445464748494a4b4c4d4e4f';
  TestDataSet.TestData[0].InitVector  := '10111213141516';
  TestDataSet.TestData[0].PT          := '20212223';
  TestDataSet.TestData[0].AAD         := '0001020304050607'; // hdr1 in initial source
  TestDataSet.TestData[0].CT          := '7162015b';
  TestDataSet.TestData[0].TagResult   := '4dac255d';
  TestDataSet.TestData[0].ModifiedAAD := '';
  TestDataSet.TestData[0].ModifiedCT  := '';

  FTestDataList.Add(TestDataSet);
end;

procedure TestTDECCCM.TearDown;
begin
  inherited;

  FCipherAES.Free;
//  FTestDataLoader.Free;
  FTestDataList.Free;
end;

procedure TestTDECCCM.TestDecode;
var
  TestDataSet : TAuthenticatedCipherTestSetEntry;
  TestData    : TSingleAuthenticatedTestData;
  DecryptData : TBytes;
begin
  for TestDataSet in FTestDataList do
  begin
    try
      for TestData in TestDataSet.TestData do
      begin
        FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestData.CryptKey)),
                        BytesOf(TFormat_HexL.Decode(TestData.InitVector)),
                        $FF);

        FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
        FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                      BytesOf(TestData.AAD));

        FCipherAES.ExpectedAuthenticationResult :=
          TFormat_HexL.Decode(BytesOf(TestData.TagResult));

        DecryptData := FCipherAES.DecodeBytes(
                         TFormat_HexL.Decode(
                           BytesOf(TestData.CT)));
        FCipherAES.Done;

        CheckEquals(string(TestData.PT),
                    StringOf(TFormat_HexL.Encode(DecryptData)),
                    'Plaintext wrong for key ' +
                    string(TestData.CryptKey) + ' IV ' +
                    string(TestData.InitVector) + ' PT ' +
                    string(TestData.PT) + ' AAD ' +
                    string(TestData.AAD) + ' Exp. PT: ' +
                    string(TestData.CT) + ' Act. PT: ' +
                    StringOf(TFormat_HexL.Encode(DecryptData)));

        // Verify additional authentication data
        CheckEquals(string(TestData.TagResult),
                           StringOf(TFormat_HexL.Encode(FCipherAES.CalculatedAuthenticationResult)),
                    'Authentication tag wrong for key ' +
                    string(TestData.CryptKey) + ' IV ' +
                    string(TestData.InitVector) + ' PT ' +
                    string(TestData.PT) + ' AAD ' +
                    string(TestData.AAD) + ' Exp. AuthTag: ' +
                    string(TestData.TagResult) + ' Act. AuthTag: ' +
                    StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));
      end;
    except
      on E: Exception do
        Status('CryptKey ' + string(TestData.CryptKey) +
          ' ' + E.ClassName + ': ' + E.Message);
    end;
  end;
end;

procedure TestTDECCCM.TestInitFailureIVTooLong;
begin
  CheckException(DoTestInitFailureIVTooLong,
                 EDECNonceLengthException,
                 'Init vector too long not detected');
end;

procedure TestTDECCCM.DoTestInitFailureIVTooLong;
var
  CipherAES : TCipher_AES;
begin
  CipherAES := TCipher_AES.Create;

  try
    CipherAES.Mode := cmCCM;
    CipherAES.Init(BytesOf(TFormat_HexL.Decode('000102030405060708')),
                   BytesOf(TFormat_HexL.Decode('0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d')),
                   $FF);
  finally
    CipherAES.Free;
  end;
end;

procedure TestTDECCCM.TestInitFailureIVTooShort;
begin
  CheckException(DoTestInitFailureIVTooShort,
                 EDECNonceLengthException,
                 'Init vector too long not detected');
end;

procedure TestTDECCCM.TestInitIV;
var
  Key : TBytes;
  IV  : TBytes;
  i   : Integer;
begin
  Key := [1, 2, 3, 4, 5, 6, 7, 8];

  // Legal CCM nonce lengths are 7..13; Init raising would fail the test
  for i := 7 to 13 do
  begin
    SetLength(IV, i);
    FillChar(IV[0], length(IV), $FF);

    FCipherAES.Init(Key, IV, $FF, pmNone);
    // Real assertion: Init must leave the cipher in CCM mode (no exception = length accepted)
    Check(FCipherAES.Mode = TCipherMode.cmCCM,
          'Mode must remain CCM after Init with IV length ' + i.ToString);
  end;
end;

procedure TestTDECCCM.DoTestInitFailureIVTooShort;
var
  CipherAES : TCipher_AES;
begin
  CipherAES := TCipher_AES.Create;

  try
    CipherAES.Mode := cmCCM;
    CipherAES.Init(BytesOf(TFormat_HexL.Decode('000102030405060708')),
                   BytesOf(TFormat_HexL.Decode('0a0b0c0d0e0f')),
                   $FF);
  finally
    CipherAES.Free;
  end;
end;

procedure TestTDECCCM.TestEncode;
var
  TestDataSet : TAuthenticatedCipherTestSetEntry;
  TestData    : TSingleAuthenticatedTestData;
  EncryptData : TBytes;
  EncrDataStr : string;
begin
  for TestDataSet in FTestDataList do
  begin
    for TestData in TestDataSet.TestData do
    begin
      FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestData.CryptKey)),
                      BytesOf(TFormat_HexL.Decode(TestData.InitVector)),
                      $FF);

      FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
      FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                    BytesOf(TestData.AAD));

      EncryptData := FCipherAES.EncodeBytes(
                       TFormat_HexL.Decode(
                         BytesOf(TestData.PT)));
      FCipherAES.Done;

      EncrDataStr := StringOf(TFormat_HexL.Encode(EncryptData));
      CheckEquals(string(TestData.CT),
                  EncrDataStr,
                  'Cipher text wrong for Key ' +
                  string(TestData.CryptKey) + ' IV ' +
                  string(TestData.InitVector) + ' PT ' +
                  string(TestData.PT) + ' AAD ' +
                  string(TestData.AAD) + ' Exp.: ' +
                  string(TestData.CT) + ' Act.: ' +
                  EncrDataStr);

      // Verify additional authentication data
      CheckEquals(string(TestData.TagResult),
                         StringOf(TFormat_HexL.Encode(FCipherAES.CalculatedAuthenticationResult)),
                  'Authentication tag wrong for Key ' +
                  string(TestData.CryptKey) + ' IV ' +
                  string(TestData.InitVector) + ' PT ' +
                  string(TestData.PT) + ' AAD ' +
                  string(TestData.AAD) + ' Exp.: ' +
                  string(TestData.TagResult) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));
    end;
  end;
end;

procedure TestTDECCCM.TestGetExpectedAuthenticationResult;
var
  Exp, Act: TBytes;
begin
  SetLength(Exp, 4);
  Exp := [1, 2, 3, 4];
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 4');

  SetLength(Exp, 0);
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 0');
end;

function TestTDECCCM.IsEqual(const a, b : TBytes):Boolean;
begin
  if (length(a) <> length(b)) then
    Result := false
  else
    if (Length(a) > 0) then
      Result := CompareMem(@a[0], @b[0], length(a))
    else
      Result := true;
end;

procedure TestTDECCCM.TestDecodeStream;
var
  ctbStream   : TBytesStream;
  ctBytes     : TBytes;
  TestDataSet : TAuthenticatedCipherTestSetEntry;
  TestData    : TSingleAuthenticatedTestData;
  DecryptData : TBytes;
  ptbStream   : TBytesStream;
begin
  for TestDataSet in FTestDataList do
  begin
    for TestData in TestDataSet.TestData do
    begin
      ctBytes := TFormat_HexL.Decode(BytesOf(TestData.CT));

      try
        FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestData.CryptKey)),
                        BytesOf(TFormat_HexL.Decode(TestData.InitVector)),
                        $FF);

        FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
        FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                      BytesOf(TestData.AAD));

        FCipherAES.ExpectedAuthenticationResult :=
          TFormat_HexL.Decode(BytesOf(TestData.TagResult));

        ctbStream := TBytesStream.Create(ctBytes);
        ptbStream := TBytesStream.Create;

        FCipherAES.DecodeStream(ctbStream, ptbStream, ctbStream.Size);

        FCipherAES.Done;

        DecryptData := ptbStream.Bytes;
        SetLength(DecryptData, ptbStream.Size);

      except
        on E: Exception do
          Status('CryptKey ' + string(TestData.CryptKey) +
            ' ' + E.ClassName + ': ' + E.Message);
      end;
      FreeAndNil(ptbStream);
      FreeAndNil(ctbStream);

      CheckEquals(string(TestData.PT),
                  StringOf(TFormat_HexL.Encode(DecryptData)),
                  'Plaintext wrong for key ' +
                  string(TestData.CryptKey) + ' IV ' +
                  string(TestData.InitVector) + ' PT ' +
                  string(TestData.PT) + ' AAD ' +
                  string(TestData.AAD) + ' Exp.: ' +
                  string(TestData.CT) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(DecryptData)));

      // Verify additional authentication data
      CheckEquals(string(TestData.TagResult),
                         StringOf(TFormat_HexL.Encode(FCipherAES.CalculatedAuthenticationResult)),
                  'Authentication tag wrong for key ' +
                  string(TestData.CryptKey) + ' IV ' +
                  string(TestData.InitVector) + ' PT ' +
                  string(TestData.PT) + ' AAD ' +
                  string(TestData.AAD) + ' Exp.: ' +
                  string(TestData.TagResult) + ' Act.: ' +
                  StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));
    end;
  end;
end;

procedure TestTDECCCM.TestEncodeStream;
begin
  // -1 to disable chunking
  DoTestEncodeStream_LoadAndTestCAVSData(-1);
end;

procedure TestTDECCCM.DoTestAuthenticationBitLengthWrong;
begin
  FCipherAES.AuthenticationResultBitLength := FTestBitLength;
end;

procedure TestTDECCCM.DoTestEncodeStream_LoadAndTestCAVSData(const
    aMaxChunkSize: Int64);
var
  TestDataSet : TAuthenticatedCipherTestSetEntry;
  curSetIndex: Integer;
begin
  for curSetIndex := 0 to FTestDataList.Count - 1 do
  begin
    TestDataSet := FTestDataList[curSetIndex];
    DoTestEncodeStream_TestSingleSet(curSetIndex, 0, aMaxChunkSize);
  end;
end;

// Deferred: multi-call CCM streams (AEAD roadmap) — former TestEncodeStreamChunked /
// TestEncodeLargeStream bodies intentionally not re-enabled here.

procedure TestTDECCCM.DoTestEncodeStream_TestSingleSet(const aSetIndex,
    aDataIndex: Integer; const aMaxChunkSize: Int64 = -1);
var
  ctbStream: TBytesStream;
  curChunkSize: Int64;
  dataLeftToEncode: Int64;
  ptBytes: TBytes;
  TestDataSet : TAuthenticatedCipherTestSetEntry;
  TestData    : TSingleAuthenticatedTestData;
  EncryptData : TBytes;
  ptbStream: TBytesStream;
begin
  TestDataSet := FTestDataList[aSetIndex];

  for TestData in TestDataSet.TestData do
  begin
    ptBytes := TFormat_HexL.Decode(BytesOf(TestData.PT));

    FCipherAES.Init(BytesOf(TFormat_HexL.Decode(TestData.CryptKey)),
                    BytesOf(TFormat_HexL.Decode(TestData.InitVector)),
                    $FF);

    FCipherAES.AuthenticationResultBitLength := TestDataSet.Taglen;
    FCipherAES.DataToAuthenticate            := TFormat_HexL.Decode(
                                                  BytesOf(TestData.AAD));

    ptbStream := TBytesStream.Create(ptBytes);
    ctbStream := TBytesStream.Create;
    try
      dataLeftToEncode := ptbStream.Size;
      curChunkSize := dataLeftToEncode;
      repeat
        // Apply chunking if needed
        if aMaxChunkSize > 0 then
          curChunkSize := Min(dataLeftToEncode, aMaxChunkSize);
        FCipherAES.EncodeStream(ptbStream, ctbStream, curChunkSize);
        Dec(dataLeftToEncode, curChunkSize);
      until (dataLeftToEncode = 0);

      FCipherAES.Done;

      EncryptData := ctbStream.Bytes;
      SetLength(EncryptData, ctbStream.Size);
    except
      on E: Exception do
        Status('CryptKey ' + string(TestData.CryptKey) +
          ' ' + E.ClassName + ': ' + E.Message);
    end;

    FreeAndNil(ptbStream);
    FreeAndNil(ctbStream);

    CheckEquals(string(TestData.CT),
                StringOf(TFormat_HexL.Encode(EncryptData)),
                'Cipher text wrong for Set ' + aSetIndex.ToString + ' and Data ' + aDataIndex.ToString +
                ' and Key ' + string(TestData.CryptKey) + ' IV ' +
                string(TestData.InitVector) + ' PT ' +
                string(TestData.PT) + ' AAD Exp.: ' +
                string(TestData.AAD) + ' Act.: ' +
                StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));

    // Verify additional authentication data
    CheckEquals(string(TestData.TagResult),
                       StringOf(TFormat_HexL.Encode(FCipherAES.CalculatedAuthenticationResult)),
                'Authentication tag wrong for Set ' + aSetIndex.ToString + ' and Data ' + aDataIndex.ToString +
                ' and Key ' + string(TestData.CryptKey) + ' IV ' +
                string(TestData.InitVector) + ' PT ' +
                string(TestData.PT) + ' AAD Exp.: ' +
                string(TestData.AAD) + ' Act.: ' +
                StringOf(TFormat_HexL.Encode(FCipherAES.DataToAuthenticate)));
  end;
end;

procedure TestTDECCCM.TestGetStandardAuthenticationTagBitLengths;
var
  BitLengths: TStandardBitLengths;
begin
  BitLengths := FCipherAES.GetStandardAuthenticationTagBitLengths;

  CheckEquals( 32, BitLengths[0]);
  CheckEquals( 48, BitLengths[1]);
  CheckEquals( 64, BitLengths[2]);
  CheckEquals( 80, BitLengths[3]);
  CheckEquals( 96, BitLengths[4]);
  CheckEquals(112, BitLengths[5]);
  CheckEquals(128, BitLengths[6]);
end;

procedure TestTDECCCM.TestSetExpectedAuthenticationResult;
var
  Exp, Act: TBytes;
begin
  SetLength(Exp, 4);
  Exp := [1, 2, 3, 4];
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 4');

  SetLength(Exp, 8);
  Exp := [1, 2, 3, 4, 5, 6, 7, 8];
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 8');

  SetLength(Exp, 12);
  Exp := [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 12');

  SetLength(Exp, 0);
  FCipherAES.ExpectedAuthenticationResult := Exp;
  Act := FCipherAES.ExpectedAuthenticationResult;

  CheckEquals(true, IsEqual(Exp, Act), 'Data length = 0');
end;

procedure TestTDECCCM.TestSetWrongAuthenticationBitLengths;
var
  bl : Integer;
begin
  bl := 31;
  while (bl < 128) do
  begin
    FTestBitLength := bl;
    CheckException(DoTestAuthenticationBitLengthWrong, EDECAuthLengthException);
    inc(bl, 16);
  end;

  bl := 33;
  while (bl <= 129) do
  begin
    FTestBitLength := bl;
    CheckException(DoTestAuthenticationBitLengthWrong, EDECAuthLengthException);
    inc(bl, 16);
  end;
end;

procedure TestTDECCCM.TestSetAuthenticationBitLengths;
var
  bl : Integer;
begin
  bl := 32;

  while (bl <= 128)  do
  begin
    FCipherAES.AuthenticationResultBitLength := bl;
    CheckEquals(bl, FCipherAES.AuthenticationResultBitLength);

    inc(bl, 16);
  end;
end;

procedure TestTDECCCM.TestGetDataToAuthenticate;
var
  inp, outp : TBytes;
begin
  inp := BytesOf(RawByteString('Hello'));
  FCipherAES.DataToAuthenticate := inp;
  outp := FCipherAES.DataToAuthenticate;

  CheckEquals(true, CompareMem(@inp[0], @outp[0], length(inp)),
              'Data to authenticate not properly set. Expected: ' +
              string(BytesToRawString(inp)) + ' Result: ' +
              string(BytesToRawString(outp)));
end;

procedure TestTDECCCM.TestSetDataToAuthenticate;
begin
  FCipherAES.DataToAuthenticate := BytesOf(RawByteString('Hello'));
  CheckEquals(RawByteString('Hello'),
              RawByteString(StringOf(FCipherAES.DataToAuthenticate)));

  FCipherAES.DataToAuthenticate := BytesOf(RawByteString('The quick brown fox jumped over the lazy dog'));
  CheckEquals(RawByteString('The quick brown fox jumped over the lazy dog'),
              RawByteString(StringOf(FCipherAES.DataToAuthenticate)));
end;

procedure TestTDECCCM.TestEncodeRFC3610;
begin
  DoTestRFC3610(true);
end;

procedure TestTDECCCM.TestDecodeRFC3610;
begin
  DoTestRFC3610(false);
end;

procedure TestTDECCCM.DoTestRFC3610(EncodeTest: Boolean);
type
  ta25 = array[0..24] of UInt8;
  ta10 = array[0..09] of UInt8;
const
  ctest: array[1..12] of ta25 = (
           ($58,$8C,$97,$9A,$61,$C6,$63,$D2,$F0,$66,$D0,$C2,$C0,$F9,$89,$80,$6D,$5F,$6B,$61,$DA,$C3,$84,$00,$00),
           ($72,$C9,$1A,$36,$E1,$35,$F8,$CF,$29,$1C,$A8,$94,$08,$5C,$87,$E3,$CC,$15,$C4,$39,$C9,$E4,$3A,$3B,$00),
           ($51,$B1,$E5,$F4,$4A,$19,$7D,$1D,$A4,$6B,$0F,$8E,$2D,$28,$2A,$E8,$71,$E8,$38,$BB,$64,$DA,$85,$96,$57),
           ($A2,$8C,$68,$65,$93,$9A,$9A,$79,$FA,$AA,$5C,$4C,$2A,$9D,$4A,$91,$CD,$AC,$8C,$00,$00,$00,$00,$00,$00),
           ($DC,$F1,$FB,$7B,$5D,$9E,$23,$FB,$9D,$4E,$13,$12,$53,$65,$8A,$D8,$6E,$BD,$CA,$3E,$00,$00,$00,$00,$00),
           ($6F,$C1,$B0,$11,$F0,$06,$56,$8B,$51,$71,$A4,$2D,$95,$3D,$46,$9B,$25,$70,$A4,$BD,$87,$00,$00,$00,$00),
           ($01,$35,$D1,$B2,$C9,$5F,$41,$D5,$D1,$D4,$FE,$C1,$85,$D1,$66,$B8,$09,$4E,$99,$9D,$FE,$D9,$6C,$00,$00),
           ($7B,$75,$39,$9A,$C0,$83,$1D,$D2,$F0,$BB,$D7,$58,$79,$A2,$FD,$8F,$6C,$AE,$6B,$6C,$D9,$B7,$DB,$24,$00),
           ($82,$53,$1A,$60,$CC,$24,$94,$5A,$4B,$82,$79,$18,$1A,$B5,$C8,$4D,$F2,$1C,$E7,$F9,$B7,$3F,$42,$E1,$97),
           ($07,$34,$25,$94,$15,$77,$85,$15,$2B,$07,$40,$98,$33,$0A,$BB,$14,$1B,$94,$7B,$00,$00,$00,$00,$00,$00),
           ($67,$6B,$B2,$03,$80,$B0,$E3,$01,$E8,$AB,$79,$59,$0A,$39,$6D,$A7,$8B,$83,$49,$34,$00,$00,$00,$00,$00),
           ($C0,$FF,$A0,$D6,$F0,$5B,$DB,$67,$F2,$4D,$43,$A4,$33,$8D,$2A,$A4,$BE,$D7,$B2,$0E,$43,$00,$00,$00,$00));
  ttest: array[1..12] of ta10 = (
           ($17,$E8,$D1,$2C,$FD,$F9,$26,$E0,$00,$00),
           ($A0,$91,$D5,$6E,$10,$40,$09,$16,$00,$00),
           ($4A,$DA,$A7,$6F,$BD,$9F,$B0,$C5,$00,$00),
           ($96,$C8,$61,$B9,$C9,$E6,$1E,$F1,$00,$00),
           ($51,$E8,$3F,$07,$7D,$9C,$2D,$93,$00,$00),
           ($40,$5A,$04,$43,$AC,$91,$CB,$94,$00,$00),
           ($04,$8C,$56,$60,$2C,$97,$AC,$BB,$74,$90),
           ($C1,$7B,$44,$33,$F4,$34,$96,$3F,$34,$B4),
           ($EA,$9C,$07,$E5,$6B,$5E,$B1,$7E,$5F,$4E),
           ($56,$6A,$A9,$40,$6B,$4D,$99,$99,$88,$DD),
           ($F5,$3A,$A2,$E9,$10,$7A,$8B,$6C,$02,$2C),
           ($CD,$1A,$A3,$16,$62,$E7,$AD,$65,$D6,$DB));
var
  buf, DecodeBuf   : array[0..63] of UInt8;
  pn               : Integer;
  key, nonce       : TBlock16Byte;
  i, ih, it, k     : Integer;
  plen, tlen, hlen : UInt16;
  x                : UInt32;
  b                : UInt8;
  CipherAES        : TCipher_AES;
  DataToAuth       : TBytes;
  TagResult        : TBytes;
begin
  nonce[00] := 0; // = init vector
  nonce[01] := 0;
  nonce[02] := 0;
  nonce[07] := $A0;
  nonce[08] := $A1;
  nonce[09] := $A2;
  nonce[10] := $A3;
  nonce[11] := $A4;
  nonce[12] := $A5;

  pn := 0;

  // key setup, all tests use the same one
  for i:= 0 to 15 do
    key[i] := $C0 + i;

  for it := 0 to 1 do
  begin
    tlen := 8 + 2*it; // authentication tag length

    for ih := 0 to 1 do
    begin
      hlen := 8 + 4*ih; // length of the data to authenticate
      SetLength(DataToAuth, hlen);

      for k := 31 to 33 do
      begin
        pLen := k-hlen; // plain text length?

        x := pn * $01010101+$03020100;
        inc(pn);

        // some positions of the nonce/init vector are different for each test
        nonce[03] := (x shr 24) and $ff;
        nonce[04] := (x shr 16) and $ff;
        nonce[05] := (x shr 08) and $ff;
        nonce[06] :=  x and $ff;

        b := 0;
        for i := 0 to hlen - 1 do
        begin
          DataToAuth[i] := b;
          inc(b);
        end;

        for i := 0 to pLen - 1 do
        begin
          buf[i] := b;
          inc(b);
        end;

        CipherAES := TCipher_AES256.Create;
        try
          CipherAES.Mode                          := TCipherMode.cmCCM;
          CipherAES.DataToAuthenticate            := DataToAuth;
          CipherAES.AuthenticationResultBitLength := tlen * 8;

          CipherAES.Init(Key[0], Length(Key), Nonce[0], 13, 0, pmNone);

          if EncodeTest then
          begin
            CipherAES.Encode(buf[0], buf[0], plen);
            CheckEquals(true, CompareMem(@buf,@ctest[pn],plen), 'Ciphertext wrong');
          end
          else
          begin
            CipherAES.Decode(ctest[pn], DecodeBuf[0], plen);
            CheckEquals(true, CompareMem(@buf,@DecodeBuf,plen), 'Plaintext wrong');
          end;

          TagResult := CipherAES.CalculatedAuthenticationResult;

          // Test the generated tag
          CheckEquals(true, CompareMem(@TagResult[0], @ttest[pn],tlen), 'Tag wrong');
        finally
          CipherAES.Free;
        end;
      end;
    end;
  end;
end;

initialization
  // Register all test cases to be run
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTDECCCM);
  {$ELSE}
  RegisterTest('DEC authenticated cipher modes', TestTDECCCM.Suite);
  {$ENDIF}
end.
