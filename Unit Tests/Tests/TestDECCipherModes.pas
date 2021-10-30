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
{$INCLUDE TestDefines.inc}

uses
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  System.SysUtils,
  DECCipherBase, DECCipherModes, DECCipherFormats, DECCiphers, DECTypes;

type
  /// <summary>
  ///   Class reference to be abe to specify duifferent cipher classes for
  ///   carrying out the different tests.
  /// </summary>
  TFormattedCipherClass = class of TDECFormattedCipher;

  /// <summary>
  ///   One entry in a list of tests
  /// </summary>
  TTestEntry = record
    /// <summary>
    ///   Input value, needs to be of block size length or a multiple of it
    /// </summary>
    Input           : RawByteString;
    /// <summary>
    ///   Expected output value, needs to be of block size length or a multiple of it
    /// </summary>
    Output          : RawByteString;
    /// <summary>
    ///   Expected output value which is used if Output is empty. Contains the
    ///   output in hexadecimal notation.
    /// </summary>
    OutputHex       : RawByteString;
    /// <summary>
    ///   Init Vektor für den ersten Test
    /// </summary>
    InitVector      : RawByteString;
    /// <summary>
    ///   Class reference for the cipher class used for this test.
    /// </summary>
    TestClass       : TFormattedCipherClass;
    /// <summary>
    ///   Block concatenating/padding mode
    /// </summary>
    Mode            : TCipherMode;
    /// <summary>
    ///   When true this is an authenticated block cipher mode
    /// </summary>
    IsAuthenticated : Boolean;
    /// <summary>
    ///   List of standard AuthenticationTagBitLength values for that mode.
    ///   If it is a not authenticated mode the list only contains one entry "0"
    /// </summary>
    StdAuthTagBitLen: TStandardBitLengths;
  end;

  /// <summary>
  ///   Prototype for a function to be passed to the generic test method
  /// </summary>
  /// <param name="Source">
  ///   Pointer to the source data for the operation
  /// </param>
  /// <param name="Dest">
  ///   Pointer to the memory where the result of the operation shall be stored
  /// </param>
  /// <param name="Size">
  ///   Size of the data to be processed in byte
  /// </param>
  TTestFunction = procedure(Source, Dest: PByteArray; Size: Integer) of object;

  /// <summary>
  ///   Testmethoden für Klasse TDECCipherModes
  /// </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipherModes = class(TTestCase)
  strict private
    FCipher : TDECCipherModes;

    const
      Data: array[1..27] of TTestEntry = ((Input:          'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output:          'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          TestClass:       TCipher_Null;
                                          Mode:            TCipherMode.cmECBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '000000000000000000000000';
                                          Output:    '000000000000000000000000';
                                          TestClass: TCipher_Null;
                                          Mode:      TCipherMode.cmECBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '12345678';
                                          Output:    '12345678';
                                          TestClass: TCipher_Null;
                                          Mode:      TCipherMode.cmECBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output:    '';
                                          OutputHex: 'FE5A89A7A1F4BD29DFFADFCF2239E1F581106DA64C0AE704';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmOFB8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '000000000000000000000000';
                                          Output:    '';
                                          OutputHex: '8F28FAD3D482CA51A680A4B35F479E95E0720EC2296C806C';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmOFB8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '12345678';
                                          Output:    '';
                                          OutputHex: '8E2AF9D7D184CD59';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmOFB8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output:    '';
                                          OutputHex: 'FE604D3DF9C2AE3D7839AF5BDEE8FD9078544A1996EC4F1C';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFB8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '000000000000000000000000';
                                          Output:    '';
                                          OutputHex: '8FD637FC449CF89F1E5EEBB66BED15C7F8C63B4481F74C5A';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFB8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '12345678';
                                          Output:    '';
                                          OutputHex: '8EF08D6414063543';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFB8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output:    '';
                                          OutputHex: 'FEAB3839BBA059FC1FECBF798CEF537803F10F15967E3ABD';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFS8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '000000000000000000000000';
                                          Output:    '';
                                          OutputHex: '8F9661B53B06D611BA916562F4420DA4B6EFD550BF01DA2C';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFS8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '12345678';
                                          Output:    '';
                                          OutputHex: '8EEA2F2F86159953';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFS8;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output:    '';
                                          OutputHex: 'FED41297FD52669B4221F913AF978D77292C958B2A9E289A';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmOFBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '000000000000000000000000';
                                          Output:    '';
                                          OutputHex: '8FA661E3882411E33B5B826FD2E9F217484EF6EF4FF84FF2';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmOFBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '12345678';
                                          Output:    '';
                                          OutputHex: '8EA462E78D2216EB';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmOFBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output:    '';
                                          OutputHex: 'FED41297FD52669B0DEC818A383ADA358E469BE634B7AFBC';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFSx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '000000000000000000000000';
                                          Output:    '';
                                          OutputHex: '8FA661E3882411E3DB7258A29424D11F2BB6B4607D24D5DB';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFSx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '12345678';
                                          Output:    '';
                                          OutputHex: '8EA462E78D2216EB';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFSx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input     : 'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output    : 'qsqwqsq'+#$7f+'89:;<=>/ikioikiw';
                                          InitVector: '01234567';
                                          TestClass : TCipher_NULL;
                                          Mode      : TCipherMode.cmCBCx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input     : '000000000000000000000000';
                                          Output    : '00000000' + #0#0#0#0#0#0#0#0 + '00000000';
                                          InitVector: #0#0#0#0#0#0#0#0;
                                          TestClass : TCipher_NULL;
                                          Mode      : TCipherMode.cmCBCx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input     : '000000000000000000000000';
                                          Output    : #0#1#2#3#4#5#6#7 + '01234567' + #0#1#2#3#4#5#6#7;
                                          InitVector: '01234567';
                                          TestClass : TCipher_NULL;
                                          Mode      : TCipherMode.cmCBCx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output:    '';
                                          OutputHex: 'FD73DA2F279926A19A65EFA8EBA5EEB67A778C6CD73294F5';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCTSx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '000000000000000000000000';
                                          Output:    '';
                                          OutputHex: '1D538CCCF38138A6BD4655272CC67443A0E32865EB422745';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCTSx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '12345678';
                                          Output:    '';
                                          OutputHex: '8EE274B893296F9E';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCTSx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     'ABCDEFGHIJKLMNOPQRSTUVWX';
                                          Output:    '';
                                          OutputHex: 'FED41297FD52669BF5361295F3BD937EF0644802ED92DC21';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '000000000000000000000000';
                                          Output:    '';
                                          OutputHex: '8FA661E3882411E35337C15BAE99B7CBDD988AC4FABB3368';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]),
                                         (Input:     '12345678';
                                          Output:    '';
                                          OutputHex: '8EA462E78D2216EB';
                                          TestClass: TCipher_1DES;
                                          Mode:      TCipherMode.cmCFBx;
                                          IsAuthenticated: False;
                                          StdAuthTagBitLen:[0]));

    /// <summary>
    ///   Carries out the actual encode test
    /// </summary>
    /// <param name="Data">
    ///   Array with the data definint inputs and outputs for the tests
    /// </param>
    /// <param name="Mode">
    ///   Cipher mode which shall be tested
    /// </param>
    /// <param name="TestAllModes">
    ///   if true parameter Mode will be ignored and tests for all modes be
    ///   carried out
    /// </param>
    procedure DoTestEncode(Data: array of TTestEntry; Mode: TCipherMode; TestAllModes: Boolean = false);
    /// <summary>
    ///   Carries out the actual decode test
    /// </summary>
    /// <param name="Data">
    ///   Array with the data definint inputs and outputs for the tests
    /// </param>
    /// <param name="Mode">
    ///   Cipher mode which shall be tested
    /// </param>
    /// <param name="TestAllModes">
    ///   if true parameter Mode will be ignored and tests for all modes be
    ///   carried out
    /// </param>
    procedure DoTestDecode(Data: array of TTestEntry; Mode: TCipherMode; TestAllModes: Boolean = false);

    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter
    /// </summary>
    procedure TestFailureCallToAuthenticationResultHelper;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter
    /// </summary>
    procedure TestFailureCallToAuthenticationResultBitLengthWriteHelper;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter
    /// </summary>
    procedure TestFailureCallToAuthenticationResultBitLengthReadHelper;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter
    /// </summary>
    procedure TestFailureCallToDataToAuthehticateWriteHelper;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter
    /// </summary>
    procedure TestFailureCallToDataToAuthehticateReadHelper;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter.
    ///   Simply sets FCipher.Mode to GCM.
    /// </summary>
    procedure TestFailureSetGCMMode;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter.
    ///   Tries to encrypt data using ECB-mode but data is not a multiple of
    ///   the block size (length data > 1 block)
    /// </summary>
    procedure TestFailureEncodeECBDataDoesNotMatchBlockSize;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter.
    ///   Tries to encrypt data using ECB-mode but data is not a multiple of
    ///   the block size (length data < 1 block)
    /// </summary>
    procedure TestFailureEncodeECBDataDoesNotMatchBlockSizeSmall;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter.
    ///   Tries to encrypt data using ECB-mode but data is not a multiple of
    ///   the block size (length data > 1 block)
    /// </summary>
    procedure TestFailureDecodeECBDataDoesNotMatchBlockSize;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter.
    ///   Tries to encrypt data using ECB-mode but data is not a multiple of
    ///   the block size (length data < 1 block)
    /// </summary>
    procedure TestFailureDecodeECBDataDoesNotMatchBlockSizeSmall;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter.
    ///   Attempt to call SetExpectedAuthenticationTag for non GCM mode
    /// </summary>
    procedure DoTestFailureSetExpectedAuthenticationTag;
    /// <summary>
    ///   Method needed because CheckException only allows procedure methods and
    ///   not functions as parameter.
    ///   Attempt to call GetExpectedAuthenticationTag for non GCM mode
    /// </summary>
    procedure DoTestFailureGetExpectedAuthenticationTag;
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
    procedure TestIsAuthenticated;
    procedure TestGetStandardAuthenticationTagBitLengths;
    procedure TestFailureCallToDataToAuthehticateWrite;
    procedure TestFailureCallToDataToAuthehticateRead;
    procedure TestFailureCallToAuthenticationResultBitLengthWrite;
    procedure TestFailureCallToAuthenticationResultBitLengthRead;
    procedure TestFailureCallToAuthenticationResult;
    procedure TestFailureSetExpectedAuthenticationTag;
    procedure TestFailureGetExpectedAuthenticationTag;
    procedure InitGCMBlocksizeNot128Failure;
    procedure InitGCMStreamCipherFailure;
    procedure TestEncodeECBDataDoesNotMatchBlockSizeFailureSmall;
    procedure TestEncodeECBDataDoesNotMatchBlockSizeFailure;
    procedure TestDecodeECBDataDoesNotMatchBlockSizeFailureSmall;
    procedure TestDecodeECBDataDoesNotMatchBlockSizeFailure;
  end;

implementation

uses
  DECUtil;

procedure TestTDECCipherModes.DoTestEncode(Data: array of TTestEntry; Mode: TCipherMode; TestAllModes: Boolean = false);
var
  Dest   : TBytes;
  Source : TBytes;
  i, n   : Integer;
  Result : string;
begin
  for i := Low(Data) to High(Data) do
  begin
    if not TestAllModes then
      // Skip data for other modes
      if Data[i].Mode <> Mode then
        Continue;

    FCipher := Data[i].TestClass.Create;
    FCipher.Mode := Data[i].Mode;

    CheckEquals(true, Data[i].Mode = FCipher.Mode, 'Cipher mode not properly set');

    try
      FCipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf(Data[i].InitVector), $FF);

      SetLength(Source, Length(Data[i].Input));
      FillChar(Source[0], Length(Source), $FF);

      Move(Data[i].Input[1], Source[0], Length(Data[i].Input));

      SetLength(Dest, length(Source));
      FCipher.Encode(Source[0], Dest[0], length(Source));

      // Output is noted non hexadecimal
      if Data[i].Output <> '' then
      begin
        for n := Low(Dest) to High(Dest) do
        begin
          CheckEquals(Ord(Data[i].Output[n+1]), Dest[n],
                      IntToStr(n+1) + '. position is wrong. ' +
                      IntToStr(i) + '. test series. Expected: ' +
                      string(Data[i].Output) + ' was: ' + string(DECUtil.BytesToRawString(Dest)));
        end;
      end
      else
      begin
        // Output is noted in hex
        Result := '';
        for n := Low(Dest) to High(Dest) do
          Result := Result + IntToHex(Dest[n], 2);

        {$IF CompilerVersion >= 24.0}
        for n := Low(Result) to High(Result) do
          CheckEquals(char(Data[i].OutputHex[n]), Result[n],
                      IntToStr(n+1) + '. position is wrong. ' +
                      IntToStr(i) + '. test series. Expected: ' +
                      string(Data[i].OutputHex) + ' was: ' + Result);
        {$ELSE}
        for n := 1 to Length(Result) do
          CheckEquals(char(Data[i].OutputHex[n]), Result[n],
                      IntToStr(n+1) + '. position is wrong. ' +
                      IntToStr(i) + '. test series. Expected: ' +
                      string(Data[i].OutputHex) + ' was: ' + Result);
        {$IFEND}
      end;

    finally
      FCipher.Free;
    end;
  end;
end;

procedure TestTDECCipherModes.DoTestFailureGetExpectedAuthenticationTag;
var
  Buf : TBytes;
begin
  Buf := FCipher.ExpectedAuthenticationResult;
  // Suppress warning about unused value
  if (length(Buf) > 0) then
    ;
end;

procedure TestTDECCipherModes.DoTestFailureSetExpectedAuthenticationTag;
var
  Buf : TBytes;
begin
  SetLength(Buf, 3);
  Buf := [0, 1, 2];

  FCipher.ExpectedAuthenticationResult := Buf;
end;

procedure TestTDECCipherModes.DoTestDecode(Data: array of TTestEntry; Mode: TCipherMode; TestAllModes: Boolean = false);
var
  Dest    : TBytes;
  Source  : TBytes;
  i, n, m : Integer;
begin
  for i := Low(Data) to High(Data) do
  begin
    if not TestAllModes then
      // Skip data for other modes
      if Data[i].Mode <> Mode then
        Continue;

    FCipher := Data[i].TestClass.Create;
    FCipher.Mode := Data[i].Mode;

    try
      FCipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf(Data[i].InitVector), $FF);

      if (Data[i].Output <> '') then
      begin
        SetLength(Source, Length(Data[i].Output));
        FillChar(Source[0], Length(Source), $FF);

        Move(Data[i].Output[1], Source[0], Length(Data[i].Output));
      end
      else
      begin
        SetLength(Source, Length(Data[i].OutputHex) div 2);
        FillChar(Source[0], Length(Source), $FF);

        n := 1; m := 0;

        repeat
          Source[m] := StrToInt('$' + char(Data[i].OutputHex[n]) + char(Data[i].OutputHex[n +1]));

          inc(n, 2);
          inc(m);
        until (n > Length(Data[i].OutputHex));
      end;

      SetLength(Dest, length(Source));
      FCipher.Decode(Source[0], Dest[0], length(Source));

      for n := Low(Dest) to High(Dest) do
      begin
        CheckEquals(Ord(Data[i].Input[n+1]), Dest[n],
                    IntToStr(n+1) + '. position is wrong. ' +
                    IntToStr(i) + '. test series. Expected: ' +
                    string(Data[i].Input) + ' was: ' + string(DECUtil.BytesToRawString(Dest)));
      end;

    finally
      FCipher.Free;
    end;
  end;
end;

procedure TestTDECCipherModes.TestEncodeECBx;
begin
  DoTestEncode(Data, TCipherMode.cmECBx);
end;

procedure TestTDECCipherModes.TestEncodeOFB8;
begin
  DoTestEncode(Data, TCipherMode.cmOFB8);
end;

procedure TestTDECCipherModes.TestEncodeCFB8;
begin
  DoTestEncode(Data, TCipherMode.cmCFB8);
end;

procedure TestTDECCipherModes.TestEncodeCFS8;
begin
  DoTestEncode(Data, TCipherMode.cmCFS8);
end;

procedure TestTDECCipherModes.TestEncodeCFBx;
begin
  DoTestEncode(Data, TCipherMode.cmCFBx);
end;

procedure TestTDECCipherModes.TestEncodeOFBx;
begin
  DoTestEncode(Data, TCipherMode.cmOFBx);
end;

procedure TestTDECCipherModes.TestFailureCallToAuthenticationResult;
begin
  FCipher := TCipher_RC6.Create;
  try
    FCipher.Mode := TCipherMode.cmCTSx;

    CheckException(TestFailureCallToAuthenticationResultHelper, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestFailureCallToAuthenticationResultBitLengthWrite;
begin
  FCipher := TCipher_RC6.Create;
  try
    FCipher.Mode := TCipherMode.cmCTSx;

    CheckException(TestFailureCallToAuthenticationResultBitLengthWriteHelper, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestFailureCallToAuthenticationResultBitLengthRead;
begin
  FCipher := TCipher_RC6.Create;
  try
    FCipher.Mode := TCipherMode.cmCTSx;

    CheckException(TestFailureCallToAuthenticationResultBitLengthReadHelper, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestFailureCallToDataToAuthehticateWrite;
begin
  FCipher := TCipher_RC6.Create;
  try
    FCipher.Mode := TCipherMode.cmCTSx;

    CheckException(TestFailureCallToDataToAuthehticateWriteHelper, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestFailureCallToDataToAuthehticateRead;
begin
  FCipher := TCipher_RC6.Create;
  try
    FCipher.Mode := TCipherMode.cmCTSx;

    CheckException(TestFailureCallToDataToAuthehticateReadHelper, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestFailureCallToAuthenticationResultHelper;
var
  AuthRes : TBytes;
begin
  AuthRes := FCipher.CalculatedAuthenticationResult;
end;

procedure TestTDECCipherModes.TestFailureCallToAuthenticationResultBitLengthWriteHelper;
begin
  FCipher.AuthenticationResultBitLength := 128;
end;

procedure TestTDECCipherModes.TestFailureCallToAuthenticationResultBitLengthReadHelper;
var
  Result : Integer;
begin
  Result := FCipher.AuthenticationResultBitLength;
  CheckEquals(128, Result);
end;

procedure TestTDECCipherModes.TestFailureCallToDataToAuthehticateWriteHelper;
var
  AuthData : TBytes;
begin
  SetLength(AuthData, 4);
  AuthData := [0, 1, 2, 3];
  FCipher.DataToAuthenticate := AuthData;
end;

procedure TestTDECCipherModes.TestFailureDecodeECBDataDoesNotMatchBlockSize;
var
  Source, Dest: TBytes;
begin
  FCipher.Mode := TCipherMode.cmECBx;
  FCipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf('0011223344556677'), $FF);

  SetLength(Source, 65);
  SetLength(Dest, 65);
  FillChar(Source[0], Length(Source), #1);

  FCipher.Decode(Source[0], Dest[0], Length(Dest));
end;

procedure TestTDECCipherModes.TestFailureDecodeECBDataDoesNotMatchBlockSizeSmall;
var
  Source, Dest: TBytes;
begin
  FCipher.Mode := TCipherMode.cmECBx;
  FCipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf('0011223344556677'), $FF);

  SetLength(Source, 15);
  SetLength(Dest, 15);
  FillChar(Source[0], Length(Source), #1);

  FCipher.Decode(Source[0], Dest[0], Length(Dest));
end;

procedure TestTDECCipherModes.TestFailureEncodeECBDataDoesNotMatchBlockSizeSmall;
var
  Source, Dest: TBytes;
begin
  FCipher.Mode := TCipherMode.cmECBx;
  FCipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf('0011223344556677'), $FF);

  SetLength(Source, 15);
  SetLength(Dest, 15);
  FillChar(Source[0], Length(Source), #1);

  FCipher.Encode(Source[0], Dest[0], Length(Dest));
end;

procedure TestTDECCipherModes.TestFailureEncodeECBDataDoesNotMatchBlockSize;
var
  Source, Dest: TBytes;
begin
  FCipher.Mode := TCipherMode.cmECBx;
  FCipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf('0011223344556677'), $FF);

  SetLength(Source, 65);
  SetLength(Dest, 65);
  FillChar(Source[0], Length(Source), #1);

  FCipher.Encode(Source[0], Dest[0], Length(Dest));
end;

procedure TestTDECCipherModes.TestFailureCallToDataToAuthehticateReadHelper;
var
  AuthRes : TBytes;
begin
  AuthRes := FCipher.DataToAuthenticate;
end;

procedure TestTDECCipherModes.InitGCMBlocksizeNot128Failure;
begin
  FCipher := TCipher_Blowfish.Create;
  try
    CheckException(TestFailureSetGCMMode, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.InitGCMStreamCipherFailure;
begin
  FCipher := TCipher_RC4.Create;
  try
    CheckException(TestFailureSetGCMMode, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestFailureSetExpectedAuthenticationTag;
begin
  FCipher := TCipher_RC4.Create;
  FCipher.Mode := TCipherMode.cmECBx;
  try
    CheckException(DoTestFailureSetExpectedAuthenticationTag, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestFailureGetExpectedAuthenticationTag;
begin
  FCipher := TCipher_RC4.Create;
  FCipher.Mode := TCipherMode.cmECBx;
  try
    CheckException(DoTestFailureGetExpectedAuthenticationTag, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestFailureSetGCMMode;
begin
  FCipher.Mode := TCipherMode.cmGCM;
end;

procedure TestTDECCipherModes.TestGetStandardAuthenticationTagBitLengths;
var
  i, n    : Integer;
  Cipher  : TDECCipherModes;
  BitLens : TStandardBitLengths;
begin
  for i := Low(Data) to High(Data) do
  begin
    Cipher      := Data[i].TestClass.Create;

    try
      Cipher.Mode := Data[i].Mode;
      BitLens     := Cipher.GetStandardAuthenticationTagBitLengths;

      CheckEquals(Length(Data[i].StdAuthTagBitLen), Length(BitLens),
                 'Wrong number of standard authentication bit lenghts '+
                 'for class: ' + Cipher.ClassName);

      for n := Low(BitLens) to High(BitLens) do
        CheckEquals(Data[i].StdAuthTagBitLen[n], BitLens[n],
                    'Wrong bit length ' + BitLens[n].ToString +
                    ' for class: ' + Cipher.ClassName);

    finally
      Cipher.Free;
    end;
  end;
end;

procedure TestTDECCipherModes.TestIsAuthenticated;
var
  i      : Integer;
  Cipher : TDECCipherModes;
begin
  for i := Low(Data) to High(Data) do
  begin
    Cipher      := Data[i].TestClass.Create;

    try
      Cipher.Mode := Data[i].Mode;

      CheckEquals(true, Data[i].Mode = Cipher.Mode, 'Cipher mode not properly set');
      CheckEquals(Data[i].IsAuthenticated, Cipher.IsAuthenticated,
                  'Wrong authentication mode for class: ' + Cipher.ClassName);
    finally
      Cipher.Free;
    end;
  end;
end;

procedure TestTDECCipherModes.TestEncodeCFSx;
begin
  DoTestEncode(Data, TCipherMode.cmCFSx);
end;

procedure TestTDECCipherModes.TestEncodeCBCx;
begin
  DoTestEncode(Data, TCipherMode.cmCBCx);
end;

procedure TestTDECCipherModes.TestEncodeCTSx;
begin
  DoTestEncode(Data, TCipherMode.cmCTSx);
end;

procedure TestTDECCipherModes.TestDecodeECBDataDoesNotMatchBlockSizeFailure;
begin
  FCipher := TCipher_AES.Create;
  try
    CheckException(TestFailureDecodeECBDataDoesNotMatchBlockSize, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestDecodeECBDataDoesNotMatchBlockSizeFailureSmall;
begin
  FCipher := TCipher_AES.Create;
  try
    CheckException(TestFailureDecodeECBDataDoesNotMatchBlockSizeSmall, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestDecodeECBx;
begin
  DoTestDecode(Data, TCipherMode.cmECBx);
end;

procedure TestTDECCipherModes.TestDecodeOFB8;
begin
  DoTestDecode(Data, TCipherMode.cmOFB8);
end;

procedure TestTDECCipherModes.TestDecodeCFB8;
begin
  DoTestDecode(Data, TCipherMode.cmCFB8);
end;

procedure TestTDECCipherModes.TestDecodeCFS8;
begin
  DoTestDecode(Data, TCipherMode.cmCFS8);
end;

procedure TestTDECCipherModes.TestDecodeCFBx;
begin
  DoTestDecode(Data, TCipherMode.cmCFBx);
end;

procedure TestTDECCipherModes.TestDecodeOFBx;
begin
  DoTestDecode(Data, TCipherMode.cmOFBx);
end;

procedure TestTDECCipherModes.TestDecodeCFSx;
begin
  DoTestDecode(Data, TCipherMode.cmCFSx);
end;

procedure TestTDECCipherModes.TestDecodeCBCx;
begin
  DoTestDecode(Data, TCipherMode.cmCBCx);
end;

procedure TestTDECCipherModes.TestDecodeCTSx;
begin
  DoTestDecode(Data, TCipherMode.cmCTSx);
end;

procedure TestTDECCipherModes.TestEncodeECBDataDoesNotMatchBlockSizeFailure;
begin
  FCipher := TCipher_AES.Create;
  try
    CheckException(TestFailureEncodeECBDataDoesNotMatchBlockSize, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestEncodeECBDataDoesNotMatchBlockSizeFailureSmall;
begin
  FCipher := TCipher_AES.Create;
  try
    CheckException(TestFailureEncodeECBDataDoesNotMatchBlockSizeSmall, EDECCipherException);
  finally
    FCipher.Free;
  end;
end;

procedure TestTDECCipherModes.TestEncode;
begin
  DoTestEncode(Data, TCipherMode.cmCTSx, true);
end;

procedure TestTDECCipherModes.TestDecode;
begin
  DoTestDecode(Data, TCipherMode.cmCTSx, true);
end;

initialization
  // Register all test cases to be run
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTDECCipherModes);
  {$ELSE}
  RegisterTest(TestTDECCipherModes.Suite);
  {$ENDIF}
end.
