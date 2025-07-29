unit TestDECChaChaPoly1305;

interface

uses {$IFDEF DUnitX}
     DUnitX.TestFramework,DUnitX.DUnitCompatibility,
     {$ELSE}
     TestFramework,
     {$ENDIF}
     System.SysUtils, Generics.Collections, System.Math,
     DECBaseClass, System.JSON,
     DECCipherBase, DECCipherModes, DECCipherFormats, DECCiphers;


type
// Testmethods for class TDECCipher
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestChaCha20Poly1305 = class(TTestCase)
  private
    type
      TJsonTestCase = record
        key : TBytes;
        iv : TBytes;
        msg : TBytes;
        aad : TBytes;
        tag : TBytes;
        enc : TBytes;
        isValid : boolean;
      end;
      TTestEnumerator = class(TEnumerable<TJsonTestCase>)
      private
        fTests : TList<TJsonTestCase>;
      protected
        function DoGetEnumerator: TEnumerator<TJsonTestCase>; override;
      public
        constructor Create(const aTestFile : string);
        destructor Destroy; override;
      end;
  private
    fTests : TTestEnumerator;

    function IterTests : TTestEnumerator;
  published
    procedure TestPoly1305;
    procedure TestChaCha20_Poly1305_KeySetup;
    procedure TestChaCha20_Poly1305_AEAD;
    procedure TestChaChaEncodeDecodeSpeed;

    procedure TestXChaCha_Poly1305_AEAD;
    // test suite code
    procedure TestEncode;
    procedure TestDecode;

    destructor Destroy; override;
  end;
implementation

uses DECCipherModesPoly1305, System.Diagnostics, classes, DECFormat, DECTypes,
      System.JSON.Readers;


// ###########################################
// ####
// ###########################################

{ TestTDECGCM }
type
  THackChaChaCipher = class(TCipher_chacha20);


procedure TestChaCha20Poly1305.TestChaCha20_Poly1305_KeySetup;
// test vector of chapter 2.6.2 in RFC 7538
const cKey : TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                       $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];
      cNonce : TBytes = [$00, $00, $00, $00, $00, $01, $02, $03, $04, $05, $06, $07];

      cChaChaMtx : TChaChaMtx = ($8ba0d58a, $cc815f90, $27405081, $7194b24a,
                                 $37b633a8, $a50dfde3, $e2b8db08, $46a6d1fd,
                                 $7da03782, $9183a233, $148ad271, $b46773d1,
                                 $3cc1875a, $8607def1, $ca5c3086, $7085eb87);


var chaCha : TCipher_ChaCha20;
    cpuMode : TChaChaCpuMode;
begin
     for cpuMode in [cmPas, cmSSE, cmAVX] do
     begin
          TCipher_ChaCha20.CpuMode := cpuMode;
          chaCha := TCipher_ChaCha20.Create;
          try
             chaCha.Mode := cmPoly1305;
             chaCha.Init( cKey, cNonce );
             Check( THackChaChaCipher(chaCha).TestChaChaMtx(cChaChaMtx), 'Initialization failed');
          finally
                 chaCha.Free;
          end;
     end;
end;

procedure TestChaCha20Poly1305.TestChaChaEncodeDecodeSpeed;
var startStop : TStopWatch;
    encBuf : TBytes;
    decBuf_pas, decBuf_SSe, decBuf_AVX, testDecode : TBytes;
    i : Integer;
    chaCha : TCipher_ChaCha20;
    cpuMode : TChaChaCpuMode;

const cKey : TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                       $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];

      cNonce : TBytes = [$07, $00, $00, $00, $40, $43, $41, $43, $44, $45, $46, $47];

procedure EncodeBuf( var dest : TBytes );
var i : integer;
begin
     for i := 0 to 3 do
     begin
          chaCha := TCipher_ChaCha20.Create;
          try
             chaCha.Mode := cmECBx;
             chaCha.Init(cKey, cNonce);

             dest := chaCha.EncodeBytes(encBuf);
          finally
                 chaCha.Free;
          end;
     end;

end;

begin
     SetLength(encBuf, 10000000);

     for i := 0 to Length(encBuf) - 1 do
          encBuf[i] := Byte(Random(255));


     SetLength(decBuf_pas, Length(encBuf));
     SetLength(decBuf_sse, Length(encBuf));
     SetLength(decBuf_avx, Length(encBuf));
     SetLength(testDecode, Length(encBuf));

     // ###########################################
     // #### Perform encryption of all 3 types
     //
     TCipher_ChaCha20.CpuMode := cmPas;
     startStop.Reset;
     startStop.Start;
     EncodeBuf( decbuf_pas );
     startStop.Stop;
     Status( Format( 'Pas Encoding took %dms', [startStop.ElapsedMilliseconds]));

     TCipher_ChaCha20.CpuMode := cmSSE;
     startStop.Reset;
     startStop.Start;
     EncodeBuf( decbuf_sse );
     startStop.Stop;
     Status( Format( 'SSE Encoding took %dms', [startStop.ElapsedMilliseconds]));

     TCipher_ChaCha20.CpuMode := cmAVX;
     startStop.Reset;
     startStop.Start;
     EncodeBuf( decbuf_avx );
     startStop.Stop;
     Status( Format( 'AVX Encoding took %dms', [startStop.ElapsedMilliseconds]));


     Check( CompareMem( @decbuf_pas[0], @decBuf_sse[0], Length(decBuf_sse)), 'SSE encoding failed');
     Check( CompareMem( @decbuf_pas[0], @decBuf_sse[0], Length(decBuf_sse)), 'avx encoding failed');


     // test decode
     for cpuMode in [cmPas, cmSSE, cmAVX] do
     begin
          TCipher_ChaCha20.CpuMode := cpuMode;
          chaCha := TCipher_ChaCha20.Create;
          try
             chaCha.Mode := cmECBx;
             chaCha.Init(cKey, cNonce);

             testDecode := chaCha.DecodeBytes(decbuf_sse);
          finally
                 chaCha.Free;
          end;

          Check( CompareMem( @encBuf[0], @testDecode[0], Length(testDecode)), 'Dencoding failed');
     end;
end;

procedure TestChaCha20Poly1305.TestDecode;
var aTest : TJsonTestCase;
    chacha : TCipher_ChaCha20;
    decode : TBytes;
    isValid : boolean;
begin
     isValid := False; // satisfy compiler
     for aTest in IterTests do
     begin
          try
             chacha := TCipher_ChaCha20.Create;
             try
                chacha.DataToAuthenticate := aTest.aad;
                chacha.ExpectedAuthenticationResult := aTest.tag;
                chaCha.Init( aTest.key, aTest.iv );

                decode := chaCha.DecodeBytes(aTest.enc);
                chaCha.Done;
                isValid := True;
             finally
                    chacha.Free;
             end;

             Check( Length(decode) = Length(aTest.msg), 'Decoding length test failed');
             if Length(decode) <> 0 then
                Check( Comparemem(@decode[0], @aTest.msg[0], Length(decode) ), 'Decoding failed' );
          except
                // tests marked as "invalid" (or not "valid") raise an exception
                // -> the test does not fail if the result is different to "valid"
                on E : EDECException do
                begin
                     isValid := False;
                end;
          else
              raise;
          end;

          Check( not (isValid xor aTest.isValid), 'Test failed');
     end;
end;

procedure TestChaCha20Poly1305.TestEncode;
var aTest : TJsonTestCase;
    chacha : TCipher_ChaCha20;
    encode : TBytes;
    isValid : boolean;
begin
     isValid := False; // satisfy compiler
     for aTest in IterTests do
     begin
          try
             chacha := TCipher_ChaCha20.Create;
             try
                chacha.DataToAuthenticate := aTest.aad;
                chacha.ExpectedAuthenticationResult := aTest.tag;
                chaCha.Init( aTest.key, aTest.iv );

                encode := chaCha.EncodeBytes(aTest.msg);
                chaCha.Done;
                isValid := True;
             finally
                    chacha.Free;
             end;

             Check( Length(encode) = Length(aTest.enc), 'Decoding length test failed');
             if Length(encode) <> 0 then
                Check( Comparemem(@encode[0], @aTest.enc[0], Length(encode) ), 'Encoding failed' );
          except
                // tests marked as "invalid" (or not "valid") raise an exception
                // -> the test does not fail if the result is different to "valid"
                on E : EDECException do
                begin
                     isValid := False;
                end;
          else
              raise;
          end;

          Check( not (isValid xor aTest.isValid), 'Test failed');
     end;
end;

type
  THackPly1305 = class(TPoly1305);

procedure TestChaCha20Poly1305.TestPoly1305;
const// cKey : Array of Byte = [$85, $d6, $be, $78, $57, $55, $6d, $33, $7f, $44, $52, $fe, $42, $d5, $06, $a8, $01, $0,
//                              $3, $80, $8a, $fb, $0d, $b2, $fd, $4a, $bf, $f6, $af, $41, $49, $f5, $1b ];

      // original test vector from rfc7539
      cMsg : AnsiString = 'Cryptographic Forum Research Group';  // without trailing #0!
      cS : Array of BYte = [$01, $03, $80, $8a, $fb, $0d, $b2, $fd, $4a, $bf, $f6, $af, $41, $49, $f5, $1b];
      cR : Array of Byte = [$85, $d6, $be, $78, $57, $55, $6d, $33, $7f, $44, $52, $fe, $42, $d5, $06, $a8];
      cTag : Array of Byte = [$a8, $06, $1d, $c1, $30, $51, $36, $c6, $c2, $2b, $8b, $af, $0c, $01, $27, $a9];

//      cKey1 : Array of Byte = [$ec, $07, $4c, $83, $55, $80, $74, $17, $01, $42, $5b, $62, $32, $35, $ad, $d6];
      cR1 : Array of BYte = [$85,  $1f, $c4, $0c, $34, $67, $ac, $0b, $e0, $5c, $c2, $04, $04, $f3, $f7, $00];
      cS1 : Array of BYte = [$ec, $07, $4c, $83, $55, $80, $74, $17, $01, $42, $5b, $62, $32, $35, $ad, $d6];
      cMsg1 : Array of Byte = [$f3, $f6];
      cTag1 : Array of BYte = [$88, $C3, $44, $37, $C6, $87, $7A, $3E, $90, $C1, $F8, $08, $58, $C3, $92, $F8];

var poly : TPoly1305;
    iv : T32ByteArray;
    msg : TBytes;
    calcTag : TBytes;
   // ctx : PPoly1305Ctx;
procedure InvData( data : PByte; len : integer );
var tmp : byte;
    pEnd : PByte;
begin
     pEnd := data;
     inc(pEnd, len - 1);
     while pEnd > data do
     begin
          tmp := pEnd^;
          pEnd^ := data^;
          data^ := tmp;

          inc(data);
          dec(pEnd);
     end;
end;
begin
     // test vector from https://datatracker.ietf.org/doc/html/rfc7539.html#page-15
     // RFC 7538
     FillChar(iv[0], Length(iv), 0);
     Move( cR1[0], iv[0], Length(cr));
     Move( cS1[0], iv[16], Length(cS1));

     //InvData( @iv[0], 16);
     //invData( @iv[16], 16);
     SetLength(msg, length(cMsg1));
     Move(cMsg1[0], msg[0], Length(msg));
     //InvData( @msg[0], Length(msg));

     poly := TPoly1305.Create;
     try
        THackPly1305(poly).InitInternal(iv);
        THackPly1305(poly).UpdatePoly(@msg[0], Length(msg));
        THackPly1305(poly).Finalize;

        calcTag := poly.CalculatedAuthenticationTag;
     finally
            poly.Free;
     end;

     Check(Length(cTag) = Length(calcTag), 'MAC length is wrong');
     Check( CompareMem(@cTag1[0], @calcTag[0], Length(calcTag)), 'Polynom calculated tag does not match');

     // ###########################################
     // #### second test
     FillChar(iv[0], Length(iv), 0);
     Move( cR[0], iv[0], Length(cr));
     Move( cS[0], iv[16], Length(cS1));

     SetLength(msg, length(cMsg));
     Move(cMsg[1], msg[0], Length(msg));

     poly := TPoly1305.Create;
     try
        THackPly1305(poly).InitInternal(iv);
        THackPly1305(poly).UpdatePoly(@msg[0], Length(msg));
        THackPly1305(poly).Finalize;

        calcTag := poly.CalculatedAuthenticationTag;
     finally
            poly.Free;
     end;

     Check(Length(cTag) = Length(calcTag), 'MAC length is wrong');
     Check( CompareMem(@cTag[0], @calcTag[0], Length(calcTag)), 'Polynom calculated tag does not match');
end;


function TestChaCha20Poly1305.IterTests: TTestEnumerator;
begin
     if not Assigned(fTests) then
        fTests := TTestEnumerator.Create('..\..\Unit Tests\Data\chacha20_poly1305_test.json');

     Result := fTests;
end;

procedure TestChaCha20Poly1305.TestXChaCha_Poly1305_AEAD;
// is actually the same test vector as for chacha20_poly1305
const cMsg : AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
      cAAD : TBytes = [$50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7];

      cKey : TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                       $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];

      cNonce : TBytes = [$40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $4a, $4b, $4c, $4d, $4e, $4f, $50, $51, $52, $53, $54, $55, $56, $57];

      cTag : TBytes = [$c0, $87, $59, $24, $c1, $c7, $98, $79, $47, $de, $af, $d8, $78, $0a, $cf, $49];

      cCipherText : TBytes = [$bd, $6d, $17, $9d, $3e, $83, $d4, $3b, $95, $76, $57, $94, $93, $c0, $e9, $39,
                              $57, $2a, $17, $00, $25, $2b, $fa, $cc, $be, $d2, $90, $2c, $21, $39, $6c, $bb,
                              $73, $1c, $7f, $1b, $0b, $4a, $a6, $44, $0b, $f3, $a8, $2f, $4e, $da, $7e, $39,
                              $ae, $64, $c6, $70, $8c, $54, $c2, $16, $cb, $96, $b7, $2e, $12, $13, $b4, $52,
                              $2f, $8c, $9b, $a4, $0d, $b5, $d9, $45, $b1, $1b, $69, $b9, $82, $c1, $bb, $9e,
                              $3f, $3f, $ac, $2b, $c3, $69, $48, $8f, $76, $b2, $38, $35, $65, $d3, $ff, $f9,
                              $21, $f9, $66, $4c, $97, $63, $7d, $a9, $76, $88, $12, $f6, $15, $c6, $8b, $13,
                              $b5, $2e ];
var chaCha : TCipher_XChaCha20;
    msg : TBytes;
    encr : TBytes;
    encrTag : TBytes;
    decr : TBytes;
    decodeTag : TBytes;
    cpuMode : TChaChaCpuMode;
begin
     for cpuMode in [cmPas, cmSSE, cmAVX] do
     begin
          TCipher_XChaCha20.CpuMode := cpuMode;

          SetLength(msg, Length(cMsg));
          Move( cMsg[1], msg[0], Length(msg));


          chaCha := TCipher_XChaCha20.Create;
          try
             chaCha.Mode := cmPoly1305;
             chaCha.DataToAuthenticate := cAAD;
             chaCha.Init(cKey, cNonce);
             encr := chaCha.EncodeBytes(msg);
             chaCha.Done;

             encrTag := chaCha.CalculatedAuthenticationResult;
          finally
                 chaCha.Free;
          end;

          Check( Length(cCipherText) = Length(encr), 'Encryption length is wrong');
          Check( CompareMem( @cCipherText[0],  @encr[0], Length(encr) ), 'Encryption failed');


          Check( Length(cTag) = Length(encrTag), 'Tag length is wrong');
          Check( CompareMem( @encrTag[0], @cTag[0], Length(cTag)), 'Calculated Tag is wrong');

          // ###########################################
          // #### Test decode
          chaCha := TCipher_XChaCha20.Create;
          try
             chaCha.Mode := cmPoly1305;
             chaCha.ExpectedAuthenticationResult := encrTag;
             chaCha.DataToAuthenticate := cAAD;

             chaCha.Init(cKey, cNonce);
             decr := chaCha.DecodeBytes(encr);
             chaCha.Done;

             decodeTag := chaCha.CalculatedAuthenticationResult
          finally
                 chaCha.Free;
          end;

          Check( Length(cTag) = Length(decodeTag), 'Tag length is wrong');
          Check( CompareMem( @decodeTag[0], @cTag[0], Length(cTag)), 'Calculated Tag is wrong');
     end;
end;


destructor TestChaCha20Poly1305.Destroy;
begin
     fTests.Free;

     inherited;
end;

procedure TestChaCha20Poly1305.TestChaCha20_Poly1305_AEAD;
const cMsg : AnsiString = 'Ladies and Gentlemen of the class of ''99: If I could offer you only one tip for the future, sunscreen would be it.';
      cAAD : TBytes = [$50, $51, $52, $53, $c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7];

      cKey : TBytes = [$80, $81, $82, $83, $84, $85, $86, $87, $88, $89, $8a, $8b, $8c, $8d, $8e, $8f,
                       $90, $91, $92, $93, $94, $95, $96, $97, $98, $99, $9a, $9b, $9c, $9d, $9e, $9f];

      cNonce : TBytes = [$07, $00, $00, $00, $40, $41, $42, $43, $44, $45, $46, $47];

      cTag : TBytes = [$1a, $e1, $0b, $59, $4f, $09, $e2, $6a, $7e, $90, $2e, $cb, $d0, $60, $06, $91];

      cCipherText : TBytes = [$d3, $1a, $8d, $34, $64, $8e, $60, $db, $7b, $86, $af, $bc, $53, $ef, $7e, $c2,
                              $a4, $ad, $ed, $51, $29, $6e, $08, $fe, $a9, $e2, $b5, $a7, $36, $ee, $62, $d6,
                              $3d, $be, $a4, $5e, $8c, $a9, $67, $12, $82, $fa, $fb, $69, $da, $92, $72, $8b,
                              $1a, $71, $de, $0a, $9e, $06, $0b, $29, $05, $d6, $a5, $b6, $7e, $cd, $3b, $36,
                              $92, $dd, $bd, $7f, $2d, $77, $8b, $8c, $98, $03, $ae, $e3, $28, $09, $1b, $58,
                              $fa, $b3, $24, $e4, $fa, $d6, $75, $94, $55, $85, $80, $8b, $48, $31, $d7, $bc,
                              $3f, $f4, $de, $f0, $8e, $4b, $7a, $9d, $e5, $76, $d2, $65, $86, $ce, $c6, $4b,
                              $61, $16 ];

var chaCha : TCipher_ChaCha20;
    msg : TBytes;
    encr : TBytes;
    encrTag : TBytes;
    decr : TBytes;
    decodeTag : TBytes;
    cpuMode : TChaChaCpuMode;
begin
     for cpuMode in [cmPas, cmSSE, cmAVX] do
     begin
          TCipher_ChaCha20.CpuMode := cpuMode;

          SetLength(msg, Length(cMsg));
          Move( cMsg[1], msg[0], Length(msg));


          chaCha := TCipher_ChaCha20.Create;
          try
             chaCha.Mode := cmPoly1305;
             chaCha.DataToAuthenticate := cAAD;
             chaCha.Init(cKey, cNonce);
             encr := chaCha.EncodeBytes(msg);
             chaCha.Done;

             encrTag := chaCha.CalculatedAuthenticationResult;
          finally
                 chaCha.Free;
          end;

          Check( Length(cCipherText) = Length(encr), 'Encryption length is wrong');
          Check( CompareMem( @cCipherText[0],  @encr[0], Length(encr) ), 'Encryption failed');


          Check( Length(cTag) = Length(encrTag), 'Tag length is wrong');
          Check( CompareMem( @encrTag[0], @cTag[0], Length(cTag)), 'Calculated Tag is wrong');

          // ###########################################
          // #### Test decode
          chaCha := TCipher_ChaCha20.Create;
          try
             chaCha.Mode := cmPoly1305;
             chaCha.ExpectedAuthenticationResult := encrTag;
             chaCha.DataToAuthenticate := cAAD;

             chaCha.Init(cKey, cNonce);
             decr := chaCha.DecodeBytes(encr);
             chaCha.Done;

             decodeTag := chaCha.CalculatedAuthenticationResult
          finally
                 chaCha.Free;
          end;

          Check( Length(cTag) = Length(decodeTag), 'Tag length is wrong');
          Check( CompareMem( @decodeTag[0], @cTag[0], Length(cTag)), 'Calculated Tag is wrong');
     end;
end;


{ TestChaCha20Poly1305.TTestEnumerator }

constructor TestChaCha20Poly1305.TTestEnumerator.Create(
  const aTestFile: string);
var groups : TJSONArray;
    tests : TJsonValue;
    aTest : TJsonValue;
    testFile : TJSonObject;
    testRec : TJsonTestCase;
begin
     inherited Create;

     fTests := TList<TJsonTestCase>.Create;
     with TSTringList.create do
     try
        Loadfromfile('..\..\Unit Tests\Data\chacha20_poly1305_test.json');
        testFile := TJSONObject.ParseJSONValue(Text) as TJSONObject;
     finally
            Free;
     end;

     // ###########################################
     // #### Build list of tests
     try
        groups := testFile.GetValue('testGroups') as TJsonArray;

        for tests in groups do
        begin
             for aTest in ((tests as TJsonObject).GetValue('tests') as TJsonArray) do
             begin
                  testRec.aad := BytesOf(TFormat_HexL.Decode(RawByteString(aTest.GetValue<string>('aad'))));
                  testRec.iv := BytesOf(TFormat_HexL.Decode(RawByteString(aTest.GetValue<string>('iv'))));
                  testRec.key := BytesOf(TFormat_HexL.Decode(RawByteString(aTest.GetValue<string>('key'))));
                  testRec.msg := BytesOf(TFormat_HexL.Decode(RawByteString(aTest.GetValue<string>('msg'))));
                  testRec.tag := BytesOf(TFormat_HexL.Decode(RawByteString(aTest.GetValue<string>('tag'))));
                  testRec.Enc := BytesOf(TFormat_HexL.Decode(RawByteString(aTest.GetValue<string>('ct'))));
                  testRec.isValid := SameText( aTest.GetValue<string>('result'), 'Valid');
                  fTests.Add(testRec);
             end;
        end;
     finally
            testFile.Free;
     end;
end;

destructor TestChaCha20Poly1305.TTestEnumerator.Destroy;
begin
     fTests.Free;

     inherited;
end;

function TestChaCha20Poly1305.TTestEnumerator.DoGetEnumerator: TEnumerator<TJsonTestCase>;
begin
     Result := fTests.GetEnumerator;
end;

initialization
  // Register all test cases to be run
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TPoly1305);
  {$ELSE}
  RegisterTest(TestChaCha20Poly1305.Suite);
  {$ENDIF}

end.
