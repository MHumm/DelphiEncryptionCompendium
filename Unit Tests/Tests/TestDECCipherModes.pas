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
  DECCipherBase, DECCipherModes, System.SysUtils;

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
    ///   Init Vektor für den ersten Test
    /// </summary>
    InitVector : RawByteString;
  end;

  /// <summary>
  ///   Prototype for a function to be passed to the generic test method
  /// </summary>
  TTestFunction = procedure(Source, Dest: PByteArray; Size: Integer) of object;

  /// <summary>
  ///   Testmethoden für Klasse TDECCipherModes
  /// </summary>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipherModes = class(TTestCase)
  strict private
    FDECPaddedCipher: TTestableCipherModes;
  private
    procedure DoTest(Data: array of TTestEntry; TestFunction: TTestFunction);
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
begin
  for i := Low(Data) to High(Data) do
  begin
    FDECPaddedCipher.Init(BytesOf(RawByteString('ABCDEFGH')), BytesOf(Data[i].InitVector), $FF);

    FillChar(Source[0], Length(Source), $FF);
    FillChar(Dest[0],   Length(Dest),   $FF);

//    // Check whether input data has a length of a multiple of the block size
//    if ((Length(Data[i].Input) mod FDECPaddedCipher.Context.BlockSize) <> 0) or
//       () then
//    begin
//      Fail('Length of input data is not a multiple of block size. ' +
//            i.ToString + '. test series');
//    end
//    else
//    begin
    Move(Data[i].Input[1], Source[0], Length(Data[i].Input));

    TestFunction(@Source, @Dest, Length(Data[i].Input));

    for n := Low(Dest) to Length(Data[i].Output)-1 do
      CheckEquals(Ord(Data[i].Output[n+1]), Dest[n],
                  IntToStr(n+1) + '. position is wrong. ' +
                  IntToStr(i) + '. test series');
//    end;
  end;
end;

procedure TestTDECCipherModes.TestEncodeECBx;
const
  Data: array[1..3] of TTestEntry = ((Input: 'ABCDEFGHIJKLMNOPQRSTUVWX'; Output: 'ABCDEFGHIJKLMNOPQRSTUVWX'),
                                     (Input: '000000000000000000000000'; Output: '000000000000000000000000'),
                                     (Input: '12345678'; Output: '12345678')); //,
//                                     (Input: ''; Output: ''));
begin
  DoTest(Data, FDECPaddedCipher.EncodeECBx);
end;

procedure TestTDECCipherModes.TestEncodeOFB8;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.EncodeOFB8(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestEncodeCFB8;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.EncodeCFB8(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestEncodeCFS8;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.EncodeCFS8(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestEncodeCFBx;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.EncodeCFBx(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestEncodeOFBx;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.EncodeOFBx(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestEncodeCFSx;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.EncodeCFSx(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestEncodeCBCx;
const
  Data: array[1..3] of TTestEntry = ((Input     : 'ABCDEFGHIJKLMNOPQRSTUVWX';
                                      Output    : 'qsqwqsq'+#$7f+'89:;<=>/ikioikiw';
                                      InitVector: '01234567'),
                                     (Input     : '000000000000000000000000';
                                      Output    : '00000000' + #0#0#0#0#0#0#0#0 + '00000000';
                                      InitVector: #0#0#0#0#0#0#0#0),
                                     (Input     : '000000000000000000000000';
                                      Output    : #0#1#2#3#4#5#6#7 + '01234567' + #0#1#2#3#4#5#6#7;
                                      InitVector: '01234567'));

begin
  DoTest(Data, FDECPaddedCipher.EncodeCBCx);
end;

procedure TestTDECCipherModes.TestEncodeCTSx;
var
  Size: Integer;
  Dest: PByteArray;
  Source: PByteArray;
begin
  // TODO: Methodenaufrufparameter einrichten
  // FDECPaddedCipher.EncodeCTSx(Source, Dest, Size);
  // TODO: Methodenergebnisse prüfen
end;

procedure TestTDECCipherModes.TestDecodeECBx;
var
  Dest   : TByteArray;
  Source : TByteArray;
const
  Data: array[1..3] of TTestEntry = ((Input: 'ABCDEFGHIJKLMNOPQRSTUVWX'; Output: 'ABCDEFGHIJKLMNOPQRSTUVWX'),
                                     (Input: '000000000000000000000000'; Output: '000000000000000000000000'),
                                     (Input: '12345678'; Output: '12345678')); //,
//                                     (Input: ''; Output: ''));
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
                                      InitVector: '01234567'),
                                     (Input     : '00000000' + #0#0#0#0#0#0#0#0 + '00000000';
                                      Output    : '000000000000000000000000';
                                      InitVector: #0#0#0#0#0#0#0#0),
                                     (Input     : #0#1#2#3#4#5#6#7 + '01234567' + #0#1#2#3#4#5#6#7;
                                      Output    : '000000000000000000000000';
                                      InitVector: '01234567'));

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

