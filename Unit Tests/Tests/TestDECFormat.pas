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
unit TestDECFormat;

interface

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}

uses
  System.SysUtils, System.Classes,
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  DECBaseClass, DECTypes, DECUtil, DECFormat, DECFormatBase;

type
  /// <summary>
  ///   Type needed for the EncodeBytes und DecodeBytes test data definition
  /// </summary>
  TestRecRawByteString = record
    Input, Output: RawByteString;
  end;

  /// <summary>
  ///   Type used for some IsValid test data lists
  /// </summary>
  TestRecIsValidRawByteString = record
    Input  : RawByteString;
    Result : Boolean;
  end;

  /// <summary>
  ///   Type needed for passing the right encode or decode method to the
  ///   generic encode/decode test
  /// </summary>
  TEncodeDecodeProc = function(const data: TBytes):TBytes of Object;
  /// <summary>
  ///   Type needed for passing the right encode or decode method to the
  ///   generic encode/decode test
  /// </summary>
  TEncodeDecodeProcRawByteString = function(const data: RawByteString):RawByteString of Object;
  /// <summary>
  ///   Type needed for passing the right encode or decode method to the
  ///   generic encode/decode test
  /// </summary>
  TEncodeDecodeProcTypeless = function(const Data; Size: Integer): RawByteString of Object;

  // Basic test implementations to be shared by the individual formatting class
  // test classes to enable easier DUnit and DUnitX compatibility
  TFormatTestsBase = class(TTestCase)
  strict protected
    procedure DoTestEncodeDecodeTypeless(
      EncodeDecodeProc: TEncodeDecodeProcTypeless;
      TestData: array of TestRecRawByteString);

    procedure DoTestEncodeDecode(EncodeDecodeProc: TEncodeDecodeProc;
                                 TestData: array of TestRecRawByteString);

    procedure DoTestEncodeDecodeRawByteString(
      EncodeDecodeProc: TEncodeDecodeProcRawByteString;
      TestData: array of TestRecRawByteString);
  end;

  // Test methods for class TFormat_HEX
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_HEX = class(TFormatTestsBase)
  strict private
    FFormat_HEX: TFormat_HEX;

    const
      cTestDataEncode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF);
         Output: '546573740A09AA55ABCDEF'));

      cTestDataDecode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  '546573740A09AA55ABCDEF';
         Output: RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  private
    procedure DoTestDecodeException;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestDecodeException;
  end;

  // Test methods for class TFormat_HEXL
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_HEXL = class(TFormatTestsBase)
  strict private
    FFormat_HEXL: TFormat_HEXL;

    const
      cTestDataEncode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF);
         Output: '546573740a09aa55abcdef'));

      cTestDataDecode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  '546573740a09aa55abcdef';
         Output: RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class TFormat_DECMIME32
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_DECMIME32 = class(TFormatTestsBase)
  strict private
    FFormat_DECMIME32: TFormat_DECMIME32;

    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
         Output: 'xk3gh4jbjsklf'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
         Output: 'xk3gh4jbjsklfyc'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
         Output: 'xk3gh4jbjsklfyzk'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
         Output: 'xk3gh4jbjsklfyzkkf'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
         Output: 'xk3gh4jbjsklfyzkkpya')); // als letzter Buchstabe kommt manchmal oft ,u statt a heraus?
                                           // scheint etwas zufällig? Was ist da faul?
                                           // lt. DECTest.vec ist a richtig

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
        (Input:  '';
         Output: RawByteString('')),
        (Input:  'xk3gh4jbjsklf'; // lt. alter DECTest.vec aber xk3gh4jbjsklf f statt y ???
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
        (Input:  'xk3gh4jbjsklfyc';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
        (Input:  'xk3gh4jbjsklfyzk';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
        (Input:  'xk3gh4jbjsklfyzkkf';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
        (Input:  'xk3gh4jbjsklfyzkkpya';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class TFormat_Base64
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_Base32 = class(TFormatTestsBase)
  strict private
    FFormat_Base32: TFormat_Base32;
    const
      cTestDataEncode : array[1..7] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('f');
         Output: 'MY======'),
        (Input:  RawByteString('fo');
         Output: 'MZXQ===='),
        (Input:  RawByteString('foo');
         Output: 'MZXW6==='),
        (Input:  RawByteString('foob');
         Output: 'MZXW6YQ='),
        (Input:  RawByteString('fooba');
         Output: 'MZXW6YTB'),
        (Input:  RawByteString('foobar');
         Output: 'MZXW6YTBOI======'));

      cTestDataDecode : array[1..7] of TestRecRawByteString = (
        (Input:  '';
         Output: RawByteString('')),
        (Input:  'MY======';
         Output: RawByteString('f')),
        (Input:  'MZXQ====';
         Output:  RawByteString('fo')),
        (Input:  'MZXW6===';
         Output: RawByteString('foo')),
        (Input:  'MZXW6YQ=';
         Output: RawByteString('foob')),
        (Input:  'MZXW6YTB';
         Output: RawByteString('fooba')),
        (Input:  'MZXW6YTBOI======';
         Output: RawByteString('foobar')));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  private
    procedure DoTestDecodeException;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestDecodeException;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;


  // Test methods for class TFormat_Base64
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_Base64 = class(TFormatTestsBase)
  strict private
    FFormat_Base64: TFormat_Base64;
    const
      cTestDataEncode : array[1..12] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
         Output: 'VGVzdAoJqlU='),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
         Output: 'VGVzdAoJqlWq'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
         Output: 'VGVzdAoJqlWqVQ=='),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
         Output: 'VGVzdAoJqlWqVao='),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
         Output: 'VGVzdAoJqlWqVapV'),
        (Input:  RawByteString('f');
         Output: 'Zg=='),
        (Input:  RawByteString('fo');
         Output: 'Zm8='),
        (Input:  RawByteString('foo');
         Output: 'Zm9v'),
        (Input:  RawByteString('foob');
         Output: 'Zm9vYg=='),
        (Input:  RawByteString('fooba');
         Output: 'Zm9vYmE='),
        (Input:  RawByteString('foobar');
         Output: 'Zm9vYmFy'));

      cTestDataDecode : array[1..12] of TestRecRawByteString = (
        (Input:  '';
         Output: RawByteString('')),
        (Input:  'VGVzdAoJqlU=';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
        (Input:  'VGVzdAoJqlWq';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
        (Input:  'VGVzdAoJqlWqVQ==';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
        (Input:  'VGVzdAoJqlWqVao=';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
        (Input:  'VGVzdAoJqlWqVapV';
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)),
        (Input:  'Zg==';
         Output: RawByteString('f')),
        (Input: 'Zm8=';
         Output:  RawByteString('fo')),
        (Input:  'Zm9v';
         Output: RawByteString('foo')),
        (Input:  'Zm9vYg==';
         Output: RawByteString('foob')),
        (Input:  'Zm9vYmE=';
         Output: RawByteString('fooba')),
        (Input:  'Zm9vYmFy';
         Output: RawByteString('foobar')));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class TFormat_Radix64
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_Radix64 = class(TFormatTestsBase)
  strict private
    FFormat_Radix64: TFormat_Radix64;

    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: RawByteString('')),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
         Output: RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=XtiM')),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
         Output: RawByteString('VGVzdAoJqlWq' + #13 + #10 + '=qBH3')),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
         Output: RawByteString('VGVzdAoJqlWqVQ==' + #13 + #10 + '=Rqc1')),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
         Output: RawByteString('VGVzdAoJqlWqVao=' + #13 + #10 +'=s2dH')),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
         Output: RawByteString('VGVzdAoJqlWqVapV' + #13 + #10 +'=WEFz')));

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: RawByteString('')),
        (Input:  RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=XtiM');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
        (Input:  RawByteString('VGVzdAoJqlWq' + #13 + #10 + '=qBH3');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
        (Input:  RawByteString('VGVzdAoJqlWqVQ==' + #13 + #10 + '=Rqc1');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
        (Input:  RawByteString('VGVzdAoJqlWqVao=' + #13 + #10 +'=s2dH');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
        (Input:  RawByteString('VGVzdAoJqlWqVapV' + #13 + #10 +'=WEFz');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));
  public
    procedure SetUp; override;
    procedure TearDown; override;

    procedure DoSetCharsPerLine0;
    procedure DoTestCRCException;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestEncodeRawByteStringWithCharsPerLine;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure SetCharsPerLine0Exception;
    procedure TestCRCException;
  end;

  // Test methods for class TFormat_UU
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_BCryptBSD = class(TFormatTestsBase)
  strict private
    FFormat_BCryptBSD: TFormat_BCryptBSD;

    const
      // Source of test data: Wolfgang Erhardt's implementation
      cTestDataEncode : array[1..22] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString(#$55#$7e#$94#$f3#$4b#$f2#$86#$e8#$71#$9a#$26#$be+
                               #$94#$ac#$1e#$16#$d9#$5e#$f9#$f8#$19#$de#$e0);
         Output: 'TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
        (Input:  RawByteString(#$14+'K=i'+#$1A+'{N'+#$CF+'9'+#$CF+'s\'+#$7F#$A7+
                               #$A7#$9C);
         Output: 'DCq7YPn5Rq63x1Lad4cll.'),
        (Input:  RawByteString(#$26#$C6+'03'+#$C0+'O'+#$8B#$CB#$A2#$FE#$24#$B5+
                               't'+#$DB+'bt');
         Output: 'HqWuK6/Ng6sg9gQzbLrgb.'),
        (Input:  RawByteString(#$9B+'|'+#$9D+'*'+#$DA#$0F#$D0+'p'+
                               #$91#$C9#$15#$D1+'Qw'+#$01#$D6);
         Output: 'k1wbIrmNyFAPwPVPSVa/ze'),
        (Input:  RawByteString(#$9B#$AE#$1B#$1C#$91#$D8#$B0+':'+
                               #$F9#$C5#$89#$E4#$02#$92#$A9#$FB);
         Output: 'k42ZFHFWqBp3vWli.nIn8u'),
        (Input:  RawByteString(#$A3+'a-'+#$8C#$9A+'7'+
                               #$DA#$C2#$F9#$9D#$94#$DA#$03#$BD+'E'+#$21);
         Output: 'm0CrhHm10qJ3lXRY.5zDGO'),
        (Input:  RawByteString('z'+#$17#$B1+']'+#$FE#$1C+'K'+
                               #$E1#$0E#$C6#$A3#$AB+'G'+#$81#$83#$86);
         Output: 'cfcvVd2aQ8CMvoMpP2EBfe'),
        (Input:  RawByteString(#$9B#$EF+'M'+#$04#$E1#$F8#$F9+'/='+#$E5+'s'+
                               #$23#$F8#$17#$91#$90);
         Output: 'k87L/MF28Q673VKh8/cPi.'),
        (Input:  RawByteString(#$F8#$F2#$C9#$E4#$DB#$91#$B4#$23#$D4#$BD#$7F+
                               #$19#$BC+'7'+#$26#$12);
         Output: '8NJH3LsPrANStV6XtBakCe'),
        (Input:  RawByteString('*'+#$1F#$1D#$C7#$0A+'='+#$14+'yV'+#$A4+'o'+
                               #$EB#$E3#$01+'`'+#$17);
         Output: 'If6bvum7DFjUnE9p2uDeDu'),
        (Input:  RawByteString('N'+#$AD#$84+'Z'+#$14+','+#$9B#$C7#$99#$18#$C8+
                               'y'+#$7F+'G'+#$0E#$F5);
         Output: 'Ro0CUfOqk6cXEKf3dyaM7O'),
        (Input:  RawByteString('c'+#$1C+'UD'+#$93+'2|2'+#$F9#$C2+'m'+
                               #$9B#$E7#$D1#$8E+'L');
         Output: 'WvvTPHKwdBJ3uk0Z37EMR.'),
        (Input:  RawByteString(#$19#$94#$E6#$86+'g'+#$E8+'f'+
                               #$9E#$22#$D5#$FB#$B8+'QI/'+#$C0);
         Output: 'EXRkfkdmXn2gzds2SSitu.'),
        (Input:  RawByteString(#$02#$D1#$17+'mt'+#$15#$8E#$E2#$9C#$FF#$DA#$C6+
                               #$15#$0C#$F1#$23);
         Output: '.rCVZVOThsIa97pEDOxvGu'),
        (Input:  RawByteString('q['+#$96#$CA#$ED+'*'+#$C9+',5N'+#$D1+'l'+
                               #$1E#$19#$E3#$8A);
         Output: 'aTsUwsyowQuzRrDqFflhge'),
        (Input:  RawByteString(#$85+'r~'+#$83#$8F#$90+'I9'+#$7F#$BE#$C9#$05+'f'+
                               #$ED#$E0#$DF);
         Output: 'fVH8e28OQRj9tqiDXs1e1u'),
        (Input:  RawByteString(#$17#$A2+';'+#$87#$7F#$AA#$F5#$C3#$8E#$87#$27+
                               '.'+#$0C#$DF+'H'+#$AF);
         Output: 'D4G5f18o7aMMfwasBL7Gpu'),
        (Input:  RawByteString(#$85#$12#$AE#$0D#$0F#$AC+'N'+#$C9#$A5#$97#$8F+
                               'y'+#$B6#$17#$10+'(');
         Output: 'fPIsBO8qRqkjj273rfaOI.'),
        (Input:  RawByteString(#$1A#$CE+'-'+#$E8#$80+'}'+#$F1#$8C+'y'+#$FC#$ED+
                               'Tg'+#$8F+'8'+#$8F);
         Output: 'Eq2r4G/76Wv39MzSX262hu'),
        (Input:  RawByteString('6(Zbgu'+#$1B#$14#$BA+'-'+#$C9#$89#$F6#$D4+'1'+
                               #$26);
         Output: 'LgfYWkbzEvQ4JakH7rOvHe'),
        (Input:  RawByteString('`*'+#$F5#$A5+'d'+#$0B#$86+'a'+#$88+'R'+
                               #$86#$93#$86#$99#$AD+'E');
         Output: 'WApznUOJfkEGSmYRfnkrPO'));

      // Source of test data: Wolfgang Erhardt's implementation
      cTestDataDecode : array[1..22] of TestRecRawByteString = (
        (Input:  '';
         Output: RawByteString('')),
        (Input:  'TV4S6ytwfsfvkgY8jIucDrjc8deX1s.';
         Output: RawByteString(#$55#$7e#$94#$f3#$4b#$f2#$86#$e8#$71#$9a#$26#$be+
                               #$94#$ac#$1e#$16#$d9#$5e#$f9#$f8#$19#$de#$e0)),
        (Input:  'DCq7YPn5Rq63x1Lad4cll.';
         Output: RawByteString(#$14+'K=i'+#$1A+'{N'+#$CF+'9'+#$CF+'s\'+
                               #$7F#$A7#$A7#$9C)),
        (Input:  'HqWuK6/Ng6sg9gQzbLrgb.';
         Output: RawByteString(#$26#$C6+'03'+#$C0+'O'+#$8B#$CB#$A2#$FE#$24#$B5+
                               't'+#$DB+'bt')),
        (Input:  'k1wbIrmNyFAPwPVPSVa/ze';
         Output: RawByteString(#$9B+'|'+#$9D+'*'+#$DA#$0F#$D0+'p'+#$91#$C9#$15+
                               #$D1+'Qw'+#$01#$D6)),
        (Input:  'k42ZFHFWqBp3vWli.nIn8u';
         Output: RawByteString(#$9B#$AE#$1B#$1C#$91#$D8#$B0+':'+#$F9#$C5#$89+
                               #$E4#$02#$92#$A9#$FB)),
        (Input:  'm0CrhHm10qJ3lXRY.5zDGO';
         Output: RawByteString(#$A3+'a-'+#$8C#$9A+'7'+#$DA#$C2#$F9#$9D#$94#$DA+
                               #$03#$BD+'E'+#$21)),
        (Input:  'cfcvVd2aQ8CMvoMpP2EBfe';
         Output: RawByteString('z'+#$17#$B1+']'+#$FE#$1C+'K'+#$E1#$0E#$C6#$A3+
                               #$AB+'G'+#$81#$83#$86)),
        (Input:  'k87L/MF28Q673VKh8/cPi.';
         Output: RawByteString(#$9B#$EF+'M'+#$04#$E1#$F8#$F9+'/='+#$E5+'s'+
                               #$23#$F8#$17#$91#$90)),
        (Input:  '8NJH3LsPrANStV6XtBakCe';
         Output: RawByteString(#$F8#$F2#$C9#$E4#$DB#$91#$B4#$23#$D4#$BD#$7F#$19+
                               #$BC+'7'+#$26#$12)),
        (Input:  'If6bvum7DFjUnE9p2uDeDu';
         Output: RawByteString('*'+#$1F#$1D#$C7#$0A+'='+#$14+'yV'+#$A4+'o'+
                               #$EB#$E3#$01+'`'+#$17)),
        (Input:  'Ro0CUfOqk6cXEKf3dyaM7O';
         Output: RawByteString('N'+#$AD#$84+'Z'+#$14+','+#$9B#$C7#$99#$18#$C8+
                               'y'+#$7F+'G'+#$0E#$F5)),
        (Input:  'WvvTPHKwdBJ3uk0Z37EMR.';
         Output: RawByteString('c'+#$1C+'UD'+#$93+'2|2'+#$F9#$C2+'m'+#$9B#$E7+
                               #$D1#$8E+'L')),
        (Input:  'EXRkfkdmXn2gzds2SSitu.';
         Output: RawByteString(#$19#$94#$E6#$86+'g'+#$E8+'f'+#$9E#$22#$D5#$FB+
                               #$B8+'QI/'+#$C0)),
        (Input:  '.rCVZVOThsIa97pEDOxvGu';
         Output: RawByteString(#$02#$D1#$17+'mt'+#$15#$8E#$E2#$9C#$FF#$DA#$C6+
                               #$15#$0C#$F1#$23)),
        (Input:  'aTsUwsyowQuzRrDqFflhge';
         Output: RawByteString('q['+#$96#$CA#$ED+'*'+#$C9+',5N'+#$D1+'l'+
                               #$1E#$19#$E3#$8A)),
        (Input:  'fVH8e28OQRj9tqiDXs1e1u';
         Output: RawByteString(#$85+'r~'+#$83#$8F#$90+'I9'+#$7F#$BE#$C9#$05+
                               'f'+#$ED#$E0#$DF)),
        (Input:  'D4G5f18o7aMMfwasBL7Gpu';
         Output: RawByteString(#$17#$A2+';'+#$87#$7F#$AA#$F5#$C3#$8E#$87#$27+
                               '.'+#$0C#$DF+'H'+#$AF)),
        (Input:  'fPIsBO8qRqkjj273rfaOI.';
         Output: RawByteString(#$85#$12#$AE#$0D#$0F#$AC+'N'+#$C9#$A5#$97#$8F+
                               'y'+#$B6#$17#$10+'(')),
        (Input:  'Eq2r4G/76Wv39MzSX262hu';
         Output: RawByteString(#$1A#$CE+'-'+#$E8#$80+'}'+#$F1#$8C+'y'+#$FC#$ED+
                               'Tg'+#$8F+'8'+#$8F)),
        (Input:  'LgfYWkbzEvQ4JakH7rOvHe';
         Output: RawByteString('6(Zbgu'+#$1B#$14#$BA+'-'+#$C9#$89#$F6#$D4+
                               '1'+#$26)),
        (Input:  'WApznUOJfkEGSmYRfnkrPO';
         Output: RawByteString('`*'+#$F5#$A5+'d'+#$0B#$86+'a'+#$88+'R'+
                               #$86#$93#$86#$99#$AD+'E')));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;


  // Test methods for class TFormat_UU
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_UU = class(TFormatTestsBase)
  strict private
    FFormat_UU: TFormat_UU;

    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
         Output: '(5&5S=`H)JE4`'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
         Output: ')5&5S=`H)JE6J'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
         Output: '*5&5S=`H)JE6J50``'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
         Output: '+5&5S=`H)JE6J5:H`'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
         Output: ',5&5S=`H)JE6J5:I5'));

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
        (Input:  '';
         Output: RawByteString('')),
        (Input:  RawByteString('(5&5S=`H)JE4`');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
        (Input:  RawByteString(')5&5S=`H)JE6J');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
        (Input:  RawByteString('*5&5S=`H)JE6J50``');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
        (Input:  RawByteString('+5&5S=`H)JE6J5:H`');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
        (Input:  RawByteString(',5&5S=`H)JE6J5:I5');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  private
    procedure DoTestDecodeException;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestDecodeException;
  end;

  // Test methods for class TFormat_XX
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_XX = class(TFormatTestsBase)
  strict private
    FFormat_XX: TFormat_XX;

    const
      cTestDataEncode : array[1..6] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
         Output: '6J4JnR+c7eZI+'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA);
         Output: '7J4JnR+c7eZKe'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55);
         Output: '8J4JnR+c7eZKeJE++'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA);
         Output: '9J4JnR+c7eZKeJOc+'),
        (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55);
         Output: 'AJ4JnR+c7eZKeJOdJ'));

      cTestDataDecode : array[1..6] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('6J4JnR+c7eZI+');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55)),
        (Input:  RawByteString('7J4JnR+c7eZKe');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA)),
        (Input:  RawByteString('8J4JnR+c7eZKeJE++');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55)),
        (Input:  RawByteString('9J4JnR+c7eZKeJOc+');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA)),
        (Input:  RawByteString('AJ4JnR+c7eZKeJOdJ');
         Output: RawByteString('Test' + #10 +#9 + #$AA + #$55 + #$AA + #$55 + #$AA + #$55)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  private
    procedure DoTestDecodeException;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestDecodeException;
  end;

  // Test methods for class TFormat_ESCAPE
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_ESCAPE = class(TFormatTestsBase)
  strict private
    FFormat_ESCAPE: TFormat_ESCAPE;

    const
      cTestDataEncode : array[1..9] of TestRecRawByteString = (
        (Input:  '';
         Output: RawByteString('')),
        (Input:  RawByteString('Test' + #$AA + #$55);
         Output: RawByteString('Test\xAAU')),
        (Input:  RawByteString('Test' + #$80 + #$55);
         Output: RawByteString('Test\x80U')),
        (Input:  RawByteString('Test' + #$20 + #$55);
         Output: RawByteString('Test U')),
        (Input:  RawByteString('Test' + #$19 + #$55);
         Output: RawByteString('Test\x19U')),
        (Input:  RawByteString('Test' + #$07 + #$08 + #$09 + #$0A + #$0B + #$0C + #$0D + #$55);
         Output: RawByteString('Test\a\b\t\n\v\f\rU')),
        (Input:  RawByteString('Test\U');
         Output: RawByteString('Test\\U')),
        (Input:  RawByteString('Test\'+#$07 +'U');
         Output: RawByteString('Test\\\aU')),
        (Input:  RawByteString('Test"hello"U');
         Output: RawByteString('Test\"hello\"U')));

      cTestDataDecode : array[1..9] of TestRecRawByteString = (
        (Input:  '';
         Output: RawByteString('')),
        (Input:  RawByteString('Test\xAAU');
         Output: RawByteString('Test' + #$AA + #$55)),
        (Input:  RawByteString('Test\x80U');
         Output: RawByteString('Test' + #$80 + #$55)),
        (Input:  RawByteString('Test U');
         Output: RawByteString('Test' + #$20 + #$55)),
        (Input:  RawByteString('Test\x19U');
         Output: RawByteString('Test' + #$19 + #$55)),
        (Input:  RawByteString('Test\a\b\t\n\v\f\rU');
         Output: RawByteString('Test' + #$07 + #$08 + #$09 + #$0A + #$0B + #$0C + #$0D + #$55)),
        (Input:  RawByteString('Test\\U');
         Output: RawByteString('Test\U')),
        (Input:  RawByteString('Test\\\aU');
         Output: RawByteString('Test\'+#$07 +'U')),
        (Input:  RawByteString('Test\"hello\"U');
         Output: RawByteString('Test"hello"U')));

        cTestDataIsValid : array[1..18] of TestRecIsValidRawByteString = (
          (Input  : 'abcABC123';
           Result : true),
          (Input  : '\a';
           Result : true),
          (Input  : '\b';
           Result : true),
          (Input  : '\t';
           Result : true),
          (Input  : '\n';
           Result : true),
          (Input  : '\r';
           Result : true),
          (Input  : '\v';
           Result : true),
          (Input  : '\f';
           Result : true),
          (Input  : '\r\n';
           Result : true),
          (Input  : 'Data\tvalue';
           Result : true),
          (Input  : '\';
           Result : false),
          (Input  : '\q';
           Result : false),
          (Input  : '\X41';
           Result : true),
          (Input  : '\X';
           Result : false),
          (Input  : '\X9';
           Result : false),
          (Input  : '\XZZ';
           Result : false),
          (Input  : chr(6);
           Result : false),
          (Input  : chr(31);
           Result : false));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  protected
    procedure DoTestDecodeExceptionWrongChar;
    procedure DoTestDecodeExceptionWrongChar2;
    procedure DoTestDecodeExceptionWrongLength;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestDecodeException;
  end;

  // Test methods for class TFormat_BigEndian16
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_BigEndian16 = class(TFormatTestsBase)
  strict private
    FFormat_BigEndian16: TFormat_BigEndian16;

    const
      cTestDataEncode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF+'1');
         Output: RawByteString('eTts'+#9+#10+#$55+#$AA+#$CD+#$AB+'1'+#$EF)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class TFormat_UTF16
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_UTF16 = class(TestTFormat_BigEndian16);

  // Test methods for class TFormat_BigEndian32
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_BigEndian32 = class(TFormatTestsBase)
  strict private
    FFormat_BigEndian32: TFormat_BigEndian32;

    const
      cTestDataEncode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF+'1');
         Output: RawByteString('tseT'+#$55+#$AA+#9+#10+'1'+#$EF+#$CD+#$AB)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class TFormat_BigEndian64
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_BigEndian64 = class(TFormatTestsBase)
  strict private
    FFormat_BigEndian64: TFormat_BigEndian64;

    const
      cTestDataEncode : array[1..2] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('Test'+#10+#9+#$AA+#$55+#$AB+#$CD+#$EF+'1ABCD');
         Output: RawByteString(#$55+#$AA+#9+#10+'tseTDCBA1'+#$EF+#$CD+#$AB)));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;


  // Test methods for class TFormat_UTF8
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTFormat_UTF8 = class(TFormatTestsBase)
  strict private
    FFormat_UTF8: TFormat_UTF8;

    const
      cTestDataEncode : array[1..9] of TestRecRawByteString = (
        (Input:  RawByteString('');
         Output: ''),
        (Input:  RawByteString('ASCIi'#10#9);
         Output: RawByteString('A'#00'S'#00'C'#00'I'#00'i'#00#10#00#9#00)),
        (Input:  RawByteString('Ansi '#$C3#$B6#$C3#$A4#10#13);
         Output: RawByteString('A'#00'n'#00's'#00'i'#00' '#00'ö'#00'ä'#00#10#00#13#00)),
        (input:  Rawbytestring(#$7f); // Delete character (ASCII)
         output: Rawbytestring(#$7f#00)),
        (input:  Rawbytestring('Greek: '#$ce#$b1#$ce#$b2#$ce#$b3); // Greek alpha, beta, gamma
         output: Rawbytestring('G'#00'r'#00'e'#00'e'#00'k'#00':'#00' '#00#$b1#3#$B2#3#$B3#3)),
        (input:  Rawbytestring(#$e2#$82#$ac); // Euro sign €
         output: Rawbytestring(#$ac#$20)),
        (input:  Rawbytestring(#$f0#$9f#$98#$81); // grinning face with smiling eyes 😃
         output: Rawbytestring(#$3D#$D8#1#$DE)),
        (Input:  Rawbytestring('Marco Cant'#$C3#$B9);
         Output: Rawbytestring('M'#00'a'#00'r'#00'c'#00'o'#00' '#00'C'#00'a'#00'n'#00't'#00#$F9#00)),
        (input:  Rawbytestring('Mixed'#$D7#$A9'bag'); // (hebrew letter Shin)
         output: Rawbytestring('M'#00'i'#00'x'#00'e'#00'd'#00#$E9#$05'b'#00'a'#00'g'#00)));

      cTestDataDecode : array[1..9] of TestRecRawByteString = (
        (Input:  '';
         Output: RawByteString('')),
        (Input:  RawByteString('A'#00'S'#00'C'#00'I'#00'i'#00#10#00#9#00);
         Output: RawByteString('ASCIi'#10#9)),
        (Input:  RawByteString('A'#00'n'#00's'#00'i'#00' '#00'ö'#00'ä'#00#10#00#13#00);
         Output: RawByteString('Ansi '#$C3#$B6#$C3#$A4#10#13)),
        (Input:  Rawbytestring(#$7f#00);
         Output: Rawbytestring(#$7f)), // Delete character (ASCII)
        (Input:  Rawbytestring('G'#00'r'#00'e'#00'e'#00'k'#00':'#00' '#00#$b1#3#$B2#3#$B3#3);
         Output: Rawbytestring('Greek: '#$ce#$b1#$ce#$b2#$ce#$b3)), // Greek alpha, beta, gamma
        (Input:  Rawbytestring(#$ac#$20); // Euro sign €
         Output: Rawbytestring(#$e2#$82#$ac)),
        (Input:  Rawbytestring(#$3D#$D8#1#$DE); // grinning face with smiling eyes 😃
         Output: Rawbytestring(#$f0#$9f#$98#$81)),
        (Input:  Rawbytestring('M'#00'a'#00'r'#00'c'#00'o'#00' '#00'C'#00'a'#00'n'#00't'#00#$F9#00);
         Output: Rawbytestring('Marco Cant'#$C3#$B9)),
        (Input:  Rawbytestring('M'#00'i'#00'x'#00'e'#00'd'#00#$E9#$05'b'#00'a'#00'g'#00); // (hebrew letter Shin)
         Output: Rawbytestring('Mixed'#$D7#$A9'bag')));
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestEncodeRawByteString;
    procedure TestEncodeTypeless;
    procedure TestDecodeBytes;
    procedure TestDecodeRawByteString;
    procedure TestDecodeTypeless;
    procedure TestIsValidTypeless;
    procedure TestIsValidTBytes;
    procedure TestIsValidRawByteString;
    procedure TestClassByName;
    procedure TestIdentity;
  end;


implementation

procedure TestTFormat_HEX.DoTestDecodeException;
begin
  FFormat_HEX.Decode('ä');
end;

procedure TestTFormat_HEX.SetUp;
begin
  FFormat_HEX := TFormat_HEX.Create;
end;

procedure TestTFormat_HEX.TearDown;
begin
  FFormat_HEX.Free;
  FFormat_HEX := nil;
end;

procedure TestTFormat_HEX.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_HEX.ClassByName('TFormat_HEX');
  CheckEquals(TFormat_HEX, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_HEX.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_HEX.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEX.TestDecodeException;
begin
  CheckException(DoTestDecodeException, EDECFormatException);
end;

procedure TestTFormat_HEX.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_HEX.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEX.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_HEX.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEX.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_HEX.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEX.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_HEX.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEX.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_HEX.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEX.TestIdentity;
begin
  CheckEquals($E1B35EAB, FFormat_HEX.Identity);
end;

procedure TestTFormat_HEX.TestIsValidRawByteString;
begin
  CheckEquals(true,  TFormat_HEX.IsValid(BytesOf('')));
  CheckEquals(true,  TFormat_HEX.IsValid(BytesOf('0123456789abcdefABCDEF')));
  // Invalid character: q is not a hex char
  CheckEquals(false, TFormat_HEX.IsValid(BytesOf('1q')));
  // Hex input length needs to be a multiple of 2, if input is not empty
  CheckEquals(false, TFormat_HEX.IsValid(BytesOf('6')));
end;

procedure TestTFormat_HEX.TestIsValidTBytes;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_HEX.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('0123456789abcdefABCDEF'));
  CheckEquals(true, TFormat_HEX.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('q'));
  CheckEquals(false, TFormat_HEX.IsValid(SrcBuf));
end;

procedure TestTFormat_HEX.TestIsValidTypeless;
var
  SrcBuf: TBytes;
  p     : Pointer;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_HEX.IsValid(SrcBuf, 0));

  SrcBuf := BytesOf(RawByteString('0123456789abcdefABCDEF'));
  p := @SrcBuf[0];
  CheckEquals(true, TFormat_HEX.IsValid(p^, length(SrcBuf)));

  SrcBuf := BytesOf(RawByteString('q'));
  p := @SrcBuf[0];
  CheckEquals(false, TFormat_HEX.IsValid(p^, length(SrcBuf)));
end;

procedure TestTFormat_HEXL.SetUp;
begin
  FFormat_HEXL := TFormat_HEXL.Create;
end;

procedure TestTFormat_HEXL.TearDown;
begin
  FFormat_HEXL.Free;
  FFormat_HEXL := nil;
end;

procedure TestTFormat_HEXL.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_HEXL.ClassByName('TFormat_HEXL');
  CheckEquals(TFormat_HEXL, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_HEXL.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_HEXL.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEXL.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_HEXL.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEXL.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_HEXL.Decode, cTestDataDecode);
end;

procedure TestTFormat_HEXL.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_HEXL.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEXL.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_HEXL.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEXL.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_HEXL.Encode, cTestDataEncode);
end;

procedure TestTFormat_HEXL.TestIdentity;
begin
  CheckEquals($39D2D18D, FFormat_HEXL.Identity);
end;

procedure TestTFormat_HEXL.TestIsValidRawByteString;
begin
  CheckEquals(true, TFormat_HEXL.IsValid(BytesOf('')));
  CheckEquals(true, TFormat_HEXL.IsValid(BytesOf('0123456789abcdefABCDEF')));
  // Invalid character: q is not a hex char
  CheckEquals(false, TFormat_HEX.IsValid(BytesOf('1q')));
  // Hex input length needs to be a multiple of 2, if input is not empty
  CheckEquals(false, TFormat_HEX.IsValid(BytesOf('6')));
end;

procedure TestTFormat_HEXL.TestIsValidTBytes;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_HEXL.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('0123456789abcdefABCDEF'));
  CheckEquals(true, TFormat_HEXL.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('q'));
  CheckEquals(false, TFormat_HEXL.IsValid(SrcBuf));
end;

procedure TestTFormat_HEXL.TestIsValidTypeless;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_HEXL.IsValid(SrcBuf, 0));

  SrcBuf := BytesOf(RawByteString('0123456789abcdefABCDEF'));
  CheckEquals(true, TFormat_HEXL.IsValid(SrcBuf[0], length(SrcBuf)));

  SrcBuf := BytesOf(RawByteString('q'));
  CheckEquals(false, TFormat_HEXL.IsValid(SrcBuf[0], length(SrcBuf)));
end;

procedure TestTFormat_DECMIME32.SetUp;
begin
  FFormat_DECMIME32 := TFormat_DECMIME32.Create;
end;

procedure TestTFormat_DECMIME32.TearDown;
begin
  FFormat_DECMIME32.Free;
  FFormat_DECMIME32 := nil;
end;

procedure TestTFormat_DECMIME32.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_DECMIME32.ClassByName('TFormat_DECMIME32');
  CheckEquals(TFormat_DECMIME32, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_DECMIME32.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_DECMIME32.Decode, cTestDataDecode);
end;

procedure TestTFormat_DECMIME32.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_DECMIME32.Decode, cTestDataDecode);
end;

procedure TestTFormat_DECMIME32.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_DECMIME32.Decode, cTestDataDecode);
end;

procedure TestTFormat_DECMIME32.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_DECMIME32.Encode, cTestDataEncode);
end;

procedure TestTFormat_DECMIME32.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_DECMIME32.Encode, cTestDataEncode);
end;

procedure TestTFormat_DECMIME32.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_DECMIME32.Encode, cTestDataEncode);
end;

procedure TestTFormat_DECMIME32.TestIdentity;
begin
  CheckEquals($A7072340, FFormat_DECMIME32.Identity);
end;

procedure TestTFormat_DECMIME32.TestIsValidRawByteString;
begin
  CheckEquals(true, TFormat_DECMIME32.IsValid(BytesOf('')));

  CheckEquals(true, TFormat_DECMIME32.IsValid(BytesOf('abcdefghijklnpqrstuwxyz123456789')));
  CheckEquals(false, TFormat_DECMIME32.IsValid(BytesOf('1Q')));
  CheckEquals(true, TFormat_DECMIME32.IsValid(BytesOf('6')));
end;

procedure TestTFormat_DECMIME32.TestIsValidTBytes;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_DECMIME32.IsValid(SrcBuf));

  SrcBuf := BytesOf(cTestDataEncode[3].Output);
  CheckEquals(true, TFormat_DECMIME32.IsValid(SrcBuf));

  SrcBuf := BytesOf(RawByteString('Q'));
  CheckEquals(false, TFormat_DECMIME32.IsValid(SrcBuf));
end;

procedure TestTFormat_DECMIME32.TestIsValidTypeless;
var
  SrcBuf: TBytes;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_DECMIME32.IsValid(SrcBuf, 0));

  SrcBuf := BytesOf(cTestDataEncode[3].Output);
  CheckEquals(true, TFormat_DECMIME32.IsValid(SrcBuf[0], length(SrcBuf)));

  SrcBuf := BytesOf(RawByteString('Q'));
  CheckEquals(false, TFormat_DECMIME32.IsValid(SrcBuf[0], length(SrcBuf)));
end;

procedure TestTFormat_Base64.SetUp;
begin
  FFormat_Base64 := TFormat_Base64.Create;
end;

procedure TestTFormat_Base64.TearDown;
begin
  FFormat_Base64.Free;
  FFormat_Base64 := nil;
end;

procedure TestTFormat_Base64.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_Base64.ClassByName('TFormat_Base64');
  CheckEquals(TFormat_Base64, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_Base64.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_Base64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base64.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Base64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base64.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Base64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base64.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_Base64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Base64.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Base64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Base64.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Base64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Base64.TestIdentity;
begin
  CheckEquals($521BA151, FFormat_BASE64.Identity);
end;

procedure TestTFormat_Base64.TestIsValidRawByteString;
var
  i : Integer;
begin
  CheckEquals(true, TFormat_Base64.IsValid(BytesOf('')));

  CheckEquals(true, TFormat_Base64.IsValid(
    BytesOf('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='#$0D#$0A)));
  CheckEquals(false, TFormat_Base64.IsValid(BytesOf('abc"')));
  CheckEquals(true, TFormat_Base64.IsValid(BytesOf('6')));

  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    CheckEquals(true, TFormat_Base64.IsValid(RawByteString(cTestDataDecode[i].Input)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

procedure TestTFormat_Base64.TestIsValidTBytes;
const
  Data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='#$0D#$0A;
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_Base64.IsValid(SrcBuf));

  SetLength(SrcBuf, 1);
  for i := 0 to 255 do
  begin
    SrcBuf[0] := i;

    if (pos(chr(i), Data) > 0) then
      CheckEquals(true, TFormat_Base64.IsValid(SrcBuf),
                  'Failure at char: ' + Chr(i) + ' ')
    else
      CheckEquals(false, TFormat_Base64.IsValid(SrcBuf),
                  'Failure at char nr: ' + IntToHex(i, 8) + ' ');
  end;

  SrcBuf := BytesOf('abc"');
  CheckEquals(false, TFormat_Base64.IsValid(SrcBuf), 'Data: abc" ');

  SrcBuf := BytesOf(cTestDataDecode[3].Input);
  CheckEquals(true, TFormat_Base64.IsValid(SrcBuf),
              'Data: ' + string(cTestDataDecode[3].Input));

  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    SrcBuf := BytesOf(RawByteString(cTestDataDecode[i].Input));
    CheckEquals(true, TFormat_Base64.IsValid(SrcBuf),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

procedure TestTFormat_Base64.TestIsValidTypeless;
const
  Data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='#$0D#$0A;
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_Base64.IsValid(SrcBuf, 0));

  SetLength(SrcBuf, 1);
  for i := 0 to 255 do
  begin
    SrcBuf[0] := i;

    if (pos(chr(i), Data) > 0) then
      CheckEquals(true, TFormat_Base64.IsValid(SrcBuf[0], length(SrcBuf)),
                  'Failure at char: ' + Chr(i) + ' ')
    else
      CheckEquals(false, TFormat_Base64.IsValid(SrcBuf[0], length(SrcBuf)),
                  'Failure at char nr: ' + IntToHex(i, 8) + ' ');
  end;


  SrcBuf := BytesOf('abc"');
  CheckEquals(false, TFormat_Base64.IsValid(SrcBuf[0], length(SrcBuf)), 'Data: abc" ');

  SrcBuf := BytesOf(cTestDataDecode[3].Input);
  CheckEquals(true, TFormat_Base64.IsValid(SrcBuf[0], length(SrcBuf)),
              'Data: ' + string(cTestDataDecode[3].Input));

  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    SrcBuf := BytesOf(RawByteString(cTestDataDecode[i].Input));
    CheckEquals(true, TFormat_Base64.IsValid(SrcBuf[0], length(SrcBuf)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

procedure TestTFormat_Radix64.DoSetCharsPerLine0;
begin
  // Provoke exception
  FFormat_Radix64.SetCharsPerLine(0);
end;

procedure TestTFormat_Radix64.DoTestCRCException;
begin
  FFormat_Radix64.Decode('VGVzdAoJqlU=' + #13 + #10 +'=XtiN');
end;

procedure TestTFormat_Radix64.SetCharsPerLine0Exception;
begin
  CheckException(DoSetCharsPerLine0, EArgumentOutOfRangeException);
end;

procedure TestTFormat_Radix64.SetUp;
begin
  FFormat_Radix64 := TFormat_Radix64.Create;
end;

procedure TestTFormat_Radix64.TearDown;
begin
  FFormat_Radix64.Free;
  FFormat_Radix64 := nil;
end;

procedure TestTFormat_Radix64.TestEncodeRawByteStringWithCharsPerLine;
type
  /// <summary>
  ///   Type needed for the EncodeBytes und DecodeBytes test data definition
  /// </summary>
  TestRecCharsPerLine = record
    Input, Output: RawByteString;
    CharsPerLine : Byte;
  end;

const
  cTestDataEncode : array[1..2] of TestRecCharsPerLine = (
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=XtiM');
     CharsPerLine: 20),
    (Input:  RawByteString('Test' + #10 +#9 + #$AA + #$55);
     Output: RawByteString('VGVz' + #13 + #10 + 'dAoJ' + #13 + #10 + 'qlU=' +
                           #13 + #10 + '=Xti' + #13 + #10 + 'M');
     CharsPerLine: 4)); 
var
  i       : Integer;
  SrcBuf,
  DestBuf : TBytes;
  OldCharsPerLineValue : Cardinal;
begin
  OldCharsPerLineValue := FFormat_Radix64.GetCharsPerLine;
  for i := Low(cTestDataEncode) to High(cTestDataEncode) do
  begin
    SrcBuf := BytesOf(RawByteString(cTestDataEncode[i].Input));
    FFormat_Radix64.SetCharsPerLine(cTestDataEncode[i].CharsPerLine);

    DestBuf := FFormat_Radix64.Encode(SrcBuf);

    CheckEquals(cTestDataEncode[i].Output,
                BytesToRawString(DestBuf));
  end;
  FFormat_Radix64.SetCharsPerLine(OldCharsPerLineValue);
end;

procedure TestTFormat_Radix64.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_Radix64.ClassByName('TFormat_Radix64');
  CheckEquals(TFormat_Radix64, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_Radix64.TestCRCException;
begin
  CheckException(DoTestCRCException, EDECFormatException);
end;

procedure TestTFormat_Radix64.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_Radix64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Radix64.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Radix64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Radix64.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Radix64.Decode, cTestDataDecode);
end;

procedure TestTFormat_Radix64.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_Radix64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Radix64.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Radix64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Radix64.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Radix64.Encode, cTestDataEncode);
end;

procedure TestTFormat_Radix64.TestIdentity;
begin
  CheckEquals($B5607732, FFormat_Radix64.Identity);
end;

procedure TestTFormat_Radix64.TestIsValidRawByteString;
var
  i     : Integer;
begin
  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    CheckEquals(true, TFormat_Radix64.IsValid(cTestDataDecode[i].Input),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  // Check if wrong CRC is not being detected
  CheckEquals(false, TFormat_Radix64.IsValid('VGVzdAoJqlU=' + #13 + #10 +'=XtiN'),
              'CRC-failure not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'=XtiN' + ' ');

  CheckEquals(false, TFormat_Radix64.IsValid('VGVzdAoJqlU=' + #13 + #10 +'=YtiM'),
              'CRC-failure not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'=YtiM' + ' ');

  // No CRC present due to missing =
  CheckEquals(false, TFormat_Radix64.IsValid('VGVzdAoJqlU=' + #13 + #10 +'XtiM'),
              'CRC not present not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'XtiM' + ' ');

  // CRC has double =
  CheckEquals(false, TFormat_Radix64.IsValid('VGVzdAoJqlU=' + #13 + #10 +'XtiM'),
              'CRC not present not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'==XtiM' + ' ');
end;

procedure TestTFormat_Radix64.TestIsValidTBytes;
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    SrcBuf := BytesOf(RawByteString(cTestDataDecode[i].Input));
    CheckEquals(true, TFormat_Radix64.IsValid(SrcBuf),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  // Check if wrong CRC is not being detected
  CheckEquals(false, TFormat_Radix64.IsValid(BytesOf(RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=XtiN'))),
              'CRC-failure not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'=XtiN' + ' ');

  CheckEquals(false, TFormat_Radix64.IsValid(BytesOf(RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=YtiM'))),
              'CRC-failure not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'=YtiM' + ' ');

  // No CRC present due to missing =
  CheckEquals(false, TFormat_Radix64.IsValid(BytesOf(RawByteString('VGVzdAoJqlU=' + #13 + #10 +'XtiM'))),
              'CRC not present not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'XtiM' + ' ');

  // CRC has double =
  CheckEquals(false, TFormat_Radix64.IsValid(BytesOf(RawByteString('VGVzdAoJqlU=' + #13 + #10 +'XtiM'))),
              'CRC not present not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'==XtiM' + ' ');
end;

procedure TestTFormat_Radix64.TestIsValidTypeless;
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    SrcBuf := BytesOf(RawByteString(cTestDataDecode[i].Input));
    CheckEquals(true, TFormat_Radix64.IsValid(SrcBuf[0], length(SrcBuf)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  // Check if wrong CRC is not being detected
  SrcBuf := BytesOf(RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=XtiN'));
  CheckEquals(false, TFormat_Radix64.IsValid(SrcBuf[0], length(SrcBuf)),
              'CRC-failure not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'=XtiN' + ' ');

  SrcBuf := BytesOf(RawByteString('VGVzdAoJqlU=' + #13 + #10 +'=YtiM'));
  CheckEquals(false, TFormat_Radix64.IsValid(SrcBuf[0], length(SrcBuf)),
              'CRC-failure not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'=YtiM' + ' ');

  // No CRC present due to missing =
  SrcBuf := BytesOf(RawByteString('VGVzdAoJqlU=' + #13 + #10 +'XtiM'));
  CheckEquals(false, TFormat_Radix64.IsValid(SrcBuf[0], length(SrcBuf)),
              'CRC not present not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'XtiM' + ' ');

  // CRC has double =
  SrcBuf := BytesOf(RawByteString('VGVzdAoJqlU=' + #13 + #10 +'XtiM'));
  CheckEquals(false, TFormat_Radix64.IsValid(SrcBuf[0], length(SrcBuf)),
              'CRC not present not detected on ' + 'VGVzdAoJqlU=' + #13 + #10 +'==XtiM' + ' ');
end;

procedure TestTFormat_UU.DoTestDecodeException;
begin
  FFormat_UU.Decode('ä');
end;

procedure TestTFormat_UU.SetUp;
begin
  FFormat_UU := TFormat_UU.Create;
end;

procedure TestTFormat_UU.TearDown;
begin
  FFormat_UU.Free;
  FFormat_UU := nil;
end;

procedure TestTFormat_UU.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_UU.ClassByName('TFormat_UU');
  CheckEquals(TFormat_UU, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_UU.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_UU.Decode, cTestDataDecode);
end;

procedure TestTFormat_UU.TestDecodeException;
begin
  CheckException(DoTestDecodeException, EDECFormatException);
end;

procedure TestTFormat_UU.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_UU.Decode, cTestDataDecode);
end;

procedure TestTFormat_UU.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_UU.Decode, cTestDataDecode);
end;

procedure TestTFormat_UU.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_UU.Encode, cTestDataEncode);
end;

procedure TestTFormat_UU.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_UU.Encode, cTestDataEncode);
end;

procedure TestTFormat_UU.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_UU.Encode, cTestDataEncode);
end;

procedure TestTFormat_UU.TestIdentity;
begin
  CheckEquals($6FCCDE6F, FFormat_UU.Identity);
end;

procedure TestTFormat_UU.TestIsValidRawByteString;
var
  i     : Integer;
begin
  CheckEquals(true, TFormat_UU.IsValid(RawByteString('')),'Failure on empty string ');

  for i := Low(cTestDataDecode) to High(cTestDataDecode) do
  begin
    if cTestDataDecode[i].Input = '' then
      Continue;

    CheckEquals(true, TFormat_UU.IsValid(cTestDataDecode[i].Input),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  CheckEquals(false, TFormat_UU.IsValid(RawByteString('#$61')), 'Failure on char $61 ');
  CheckEquals(false, TFormat_UU.IsValid('(5&5S' + #$61 + '=`H)JE4`'), 'Failure on char $61 inbetween ');
  CheckEquals(false, TFormat_UU.IsValid(#$61 + '(5&5S=`H)JE4`'), 'Failure on char $61 at the beginning ');
  CheckEquals(false, TFormat_UU.IsValid('(5&5S=`H)JE4`' + #$61), 'Failure on char $61 at the end ');

  for i := $61 to $FF do
    CheckEquals(false, TFormat_UU.IsValid(RawByteString(chr(i))),
                'Failure on char #' + IntToHex(i, 8) + ' ');
end;

procedure TestTFormat_UU.TestIsValidTBytes;
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  SetLength(SrcBuf, 0);
  CheckEquals(true, TFormat_UU.IsValid(SrcBuf, length(SrcBuf)),
              'Failure on empty buffer ');

  for i := Low(cTestDataDecode) to High(cTestDataDecode) do
  begin
    if cTestDataDecode[i].Input = '' then
      Continue;

    CheckEquals(true, TFormat_UU.IsValid(BytesOf(cTestDataDecode[i].Input)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  CheckEquals(false, TFormat_UU.IsValid(BytesOf(RawByteString('#$61'))), 'Failure on char $61 ');
  CheckEquals(false, TFormat_UU.IsValid(BytesOf('(5&5S' + #$61 + '=`H)JE4`')), 'Failure on char $61 inbetween ');
  CheckEquals(false, TFormat_UU.IsValid(BytesOf(#$61 + '(5&5S=`H)JE4`')), 'Failure on char $61 at the beginning ');
  CheckEquals(false, TFormat_UU.IsValid(BytesOf('(5&5S=`H)JE4`' + #$61)), 'Failure on char $61 at the end ');

  for i := $61 to $FF do
    CheckEquals(false, TFormat_UU.IsValid(BytesOf(RawByteString(chr(i)))),
                'Failure on char #' + IntToHex(i, 8) + ' ');
end;

procedure TestTFormat_UU.TestIsValidTypeless;
var
  SrcBuf: TBytes;
  i     : Integer;
  p     : Pointer;
begin
  SetLength(SrcBuf, 0);
  p := @SrcBuf;
  CheckEquals(true, TFormat_UU.IsValid(p^, length(SrcBuf)),
              'Failure on empty buffer ');

  for i := Low(cTestDataDecode) to High(cTestDataDecode) do
  begin
    if cTestDataDecode[i].Input = '' then
      Continue;

    SrcBuf := BytesOf(cTestDataDecode[i].Input);
    p := @SrcBuf[0];
    CheckEquals(true, TFormat_UU.IsValid(p^, length(SrcBuf)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  SrcBuf := BytesOf(RawByteString('#$61'));
  p := @SrcBuf;
  CheckEquals(false, TFormat_UU.IsValid(p^, length(SrcBuf)), 'Failure on char $61 ');
  SrcBuf := BytesOf('(5&5S' + #$61 + '=`H)JE4`');
  p := @SrcBuf;
  CheckEquals(false, TFormat_UU.IsValid(p^, length(SrcBuf)), 'Failure on char $61 inbetween ');
  SrcBuf := BytesOf(#$61 + '(5&5S=`H)JE4`');
  p := @SrcBuf;
  CheckEquals(false, TFormat_UU.IsValid(p^, length(SrcBuf)), 'Failure on char $61 at the beginning ');
  SrcBuf := BytesOf('(5&5S=`H)JE4`' + #$61);
  p := @SrcBuf;
  CheckEquals(false, TFormat_UU.IsValid(p^, length(SrcBuf)), 'Failure on char $61 at the end ');

  SetLength(SrcBuf, 1);
  for i := $61 to $FF do
  begin
    SrcBuf[0] := i;
    p := @SrcBuf;
    CheckEquals(false, TFormat_UU.IsValid(p^, length(SrcBuf)),
                'Failure on char #' + IntToHex(i, 8) + ' ');
  end;
end;

procedure TestTFormat_XX.DoTestDecodeException;
begin
  FFormat_XX.Decode('ä');
end;

procedure TestTFormat_XX.SetUp;
begin
  FFormat_XX := TFormat_XX.Create;
end;

procedure TestTFormat_XX.TearDown;
begin
  FFormat_XX.Free;
  FFormat_XX := nil;
end;

procedure TestTFormat_XX.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_XX.ClassByName('TFormat_XX');
  CheckEquals(TFormat_XX, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_XX.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_XX.Decode, cTestDataDecode);
end;

procedure TestTFormat_XX.TestDecodeException;
begin
  CheckException(DoTestDecodeException, EDECFormatException);
end;

procedure TestTFormat_XX.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_XX.Decode, cTestDataDecode);
end;

procedure TestTFormat_XX.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_XX.Decode, cTestDataDecode);
end;

procedure TestTFormat_XX.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_XX.Encode, cTestDataEncode);
end;

procedure TestTFormat_XX.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_XX.Encode, cTestDataEncode);
end;

procedure TestTFormat_XX.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_XX.Encode, cTestDataEncode);
end;

procedure TestTFormat_XX.TestIdentity;
begin
  CheckEquals($A4D3DC9F, FFormat_XX.Identity);
end;

procedure TestTFormat_XX.TestIsValidRawByteString;
var
  i     : Integer;
begin
  CheckEquals(true, TFormat_XX.IsValid(RawByteString('')),'Failure on empty string ');

  for i := Low(cTestDataDecode) to High(cTestDataDecode) do
  begin
    if cTestDataDecode[i].Input = '' then
      Continue;

    CheckEquals(true, TFormat_XX.IsValid(cTestDataDecode[i].Input),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  CheckEquals(false, TFormat_XX.IsValid(RawByteString('#$2A')), 'Failure on char $2A ');
  CheckEquals(false, TFormat_XX.IsValid('6J4Jn' + #$2A + 'R+c7eZI+'), 'Failure on char $2A inbetween ');
  CheckEquals(false, TFormat_XX.IsValid(#$2A +'6J4JnR+c7eZI+'), 'Failure on char $2A at the beginning ');
  CheckEquals(false, TFormat_XX.IsValid('6J4JnR+c7eZI+' + #$2A), 'Failure on char $2A at the end ');

  CheckEquals(false, TFormat_XX.IsValid(RawByteString('#$23')), 'Failure on char $23 ');
  CheckEquals(false, TFormat_XX.IsValid('6J4Jn' + #$23 + 'R+c7eZI+'), 'Failure on char $23 inbetween ');
  CheckEquals(false, TFormat_XX.IsValid(#$23 +'6J4JnR+c7eZI+'), 'Failure on char $23 at the beginning ');
  CheckEquals(false, TFormat_XX.IsValid('6J4JnR+c7eZI+' + #$23), 'Failure on char $23 at the end ');

  for i := $7B to $FF do
    CheckEquals(false, TFormat_XX.IsValid(RawByteString(chr(i))),
                'Failure on char #' + IntToHex(i, 8) + ' ');
end;

procedure TestTFormat_XX.TestIsValidTBytes;
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  SetLength(SrcBuf, 0);
  CheckEquals(true, TFormat_XX.IsValid(SrcBuf, length(SrcBuf)),
              'Failure on empty buffer ');

  for i := Low(cTestDataDecode) to High(cTestDataDecode) do
  begin
    if cTestDataDecode[i].Input = '' then
      Continue;

    CheckEquals(true, TFormat_XX.IsValid(BytesOf(cTestDataDecode[i].Input)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  CheckEquals(false, TFormat_XX.IsValid(BytesOf(RawByteString('#$2A'))), 'Failure on char $2A ');
  CheckEquals(false, TFormat_XX.IsValid(BytesOf('6J4Jn' + #$2A + 'R+c7eZI+')), 'Failure on char $2A inbetween ');
  CheckEquals(false, TFormat_XX.IsValid(BytesOf(#$2A +'6J4JnR+c7eZI+')), 'Failure on char $2A at the beginning ');
  CheckEquals(false, TFormat_XX.IsValid(BytesOf('6J4JnR+c7eZI+' + #$2A)), 'Failure on char $2A at the end ');

  CheckEquals(false, TFormat_XX.IsValid(BytesOf(RawByteString('#$23'))), 'Failure on char $23 ');
  CheckEquals(false, TFormat_XX.IsValid(BytesOf('6J4Jn' + #$23 + 'R+c7eZI+')), 'Failure on char $23 inbetween ');
  CheckEquals(false, TFormat_XX.IsValid(BytesOf(#$23 +'6J4JnR+c7eZI+')), 'Failure on char $23 at the beginning ');
  CheckEquals(false, TFormat_XX.IsValid(BytesOf('6J4JnR+c7eZI+' + #$23)), 'Failure on char $23 at the end ');

  for i := $7B to $FF do
    CheckEquals(false, TFormat_XX.IsValid(RawByteString(chr(i))),
                'Failure on char #' + IntToHex(i, 8) + ' ');
end;

procedure TestTFormat_XX.TestIsValidTypeless;
var
  SrcBuf: TBytes;
  i     : Integer;
  p     : Pointer;
begin
  SetLength(SrcBuf, 0);
  p := @SrcBuf;
  CheckEquals(true, TFormat_XX.IsValid(p^, length(SrcBuf)),
              'Failure on empty buffer ');

  for i := Low(cTestDataDecode) to High(cTestDataDecode) do
  begin
    if cTestDataDecode[i].Input = '' then
      Continue;

    SrcBuf := BytesOf(cTestDataDecode[i].Input);
    p := @SrcBuf[0];
    CheckEquals(true, TFormat_XX.IsValid(p^, length(SrcBuf)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;

  Srcbuf := BytesOf(RawByteString('#$2A'));
  p := @SrcBuf;
  CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)), 'Failure on char $2A ');
  Srcbuf := BytesOf('6J4Jn' + #$2A + 'R+c7eZI+');
  p := @SrcBuf;
  CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)), 'Failure on char $2A inbetween ');
  Srcbuf := BytesOf(#$2A +'6J4JnR+c7eZI+');
  p := @SrcBuf;
  CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)), 'Failure on char $2A at the beginning ');
  Srcbuf := BytesOf('6J4JnR+c7eZI+' + #$2A);
  p := @SrcBuf;
  CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)), 'Failure on char $2A at the end ');

  Srcbuf := BytesOf(RawByteString('#$23'));
  p := @SrcBuf;
  CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)), 'Failure on char $23 ');
  Srcbuf := BytesOf('6J4Jn' + #$23 + 'R+c7eZI+');
  p := @SrcBuf;
  CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)), 'Failure on char $23 inbetween ');
  Srcbuf := BytesOf(#$23 +'6J4JnR+c7eZI+');
  p := @SrcBuf;
  CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)), 'Failure on char $23 at the beginning ');
  Srcbuf := BytesOf('6J4JnR+c7eZI+' + #$23);
  p := @SrcBuf;
  CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)), 'Failure on char $23 at the end ');

  SetLength(SrcBuf, 1);
  for i := $61 to $FF do
  begin
    SrcBuf[0] := i;
    p := @SrcBuf;
    CheckEquals(false, TFormat_XX.IsValid(p^, length(SrcBuf)),
                'Failure on char #' + IntToHex(i, 8) + ' ');
  end;
end;

procedure TestTFormat_ESCAPE.DoTestDecodeExceptionWrongChar;
begin
  FFormat_ESCAPE.Decode(RawByteString('\xä'));
end;

procedure TestTFormat_ESCAPE.DoTestDecodeExceptionWrongChar2;
begin
  FFormat_ESCAPE.Decode(RawByteString('\xaä'));
end;

procedure TestTFormat_ESCAPE.DoTestDecodeExceptionWrongLength;
begin
  FFormat_ESCAPE.Decode(RawByteString('\xaa\x'));
end;

procedure TestTFormat_ESCAPE.SetUp;
begin
  FFormat_ESCAPE := TFormat_ESCAPE.Create;
end;

procedure TestTFormat_ESCAPE.TearDown;
begin
  FFormat_ESCAPE.Free;
  FFormat_ESCAPE := nil;
end;

procedure TestTFormat_ESCAPE.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_ESCAPE.ClassByName('TFormat_ESCAPE');
  CheckEquals(TFormat_ESCAPE, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_ESCAPE.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_ESCAPE.Decode, cTestDataDecode);
end;

procedure TestTFormat_ESCAPE.TestDecodeException;
begin
  CheckException(DoTestDecodeExceptionWrongChar, EDECFormatException);
  CheckException(DoTestDecodeExceptionWrongChar2, EDECFormatException);
  CheckException(DoTestDecodeExceptionWrongLength, EDECFormatException);
end;

procedure TestTFormat_ESCAPE.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_ESCAPE.Decode, cTestDataDecode);
end;

procedure TestTFormat_ESCAPE.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_ESCAPE.Decode, cTestDataDecode);
end;

procedure TestTFormat_ESCAPE.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_ESCAPE.Encode, cTestDataEncode);
end;

procedure TestTFormat_ESCAPE.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_ESCAPE.Encode, cTestDataEncode);
end;

procedure TestTFormat_ESCAPE.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_ESCAPE.Encode, cTestDataEncode);
end;

procedure TestTFormat_ESCAPE.TestIdentity;
begin
  CheckEquals($168B27C3, FFormat_ESCAPE.Identity);
end;

procedure TestTFormat_ESCAPE.TestIsValidRawByteString;
var
  i   : Integer;
  Str : RawByteString;
  p   : ^Byte;
begin
  CheckEquals(true, TFormat_ESCAPE.IsValid(RawByteString('')),'Failure on empty string ');

  // check all chars in allowed range
  for i := 32 to 127 do
  begin
    // skip backslash
    if i = $5C then
      Continue;

    CheckEquals(true, TFormat_ESCAPE.IsValid(RawByteString(chr(i))),
                IntToStr(i) + ': Failure on ' + chr(i) + ' ');
  end;

  // check hex chars
  for i := 128 to 255 do
  begin
    CheckEquals(true, TFormat_ESCAPE.IsValid(RawByteString('\X' + IntToHex(i, 2))),
                IntToStr(i) + ': Failure on \X' + IntToHex(i, 2));
  end;

  // check hex chars
  for i := 0 to 31 do
  begin
    CheckEquals(true, TFormat_ESCAPE.IsValid(RawByteString('\X' + IntToHex(i, 2))),
                IntToStr(i) + ': Failure on \X' + IntToHex(i, 2));
  end;

  for i := Low(cTestDataIsValid) to High(cTestDataIsValid) do
  begin
    CheckEquals(cTestDataIsValid[i].Result,
                TFormat_ESCAPE.IsValid(cTestDataIsValid[i].Input),
                IntToStr(i) + ': Failure on ' + string(cTestDataIsValid[i].Input));
  end;

  Str := 'A';
  p := @Str[1];
  p^ := $80;

  CheckEquals(false,
              TFormat_ESCAPE.IsValid(Str),
              'Failure on ' + string(Str));
end;

procedure TestTFormat_ESCAPE.TestIsValidTBytes;
var
  i : Integer;
  b : TBytes;
begin
  CheckEquals(true, TFormat_ESCAPE.IsValid(BytesOf(RawByteString(''))),'Failure on empty string ');

  // check all chars in allowed range
  for i := 32 to 127 do
  begin
    // skip backslash
    if i = $5C then
      Continue;

    CheckEquals(true, TFormat_ESCAPE.IsValid(BytesOf(chr(i))),
                IntToStr(i) + ': Failure on ' + chr(i) + ' ');
  end;

  // check hex chars
  for i := 128 to 255 do
  begin
    CheckEquals(true, TFormat_ESCAPE.IsValid(BytesOf('\X' + IntToHex(i, 2))),
                IntToStr(i) + ': Failure on \X' + IntToHex(i, 2));
  end;

  // check hex chars
  for i := 0 to 31 do
  begin
    CheckEquals(true, TFormat_ESCAPE.IsValid(BytesOf('\X' + IntToHex(i, 2))),
                IntToStr(i) + ': Failure on \X' + IntToHex(i, 2));
  end;

  for i := Low(cTestDataIsValid) to High(cTestDataIsValid) do
  begin
    CheckEquals(cTestDataIsValid[i].Result,
                TFormat_ESCAPE.IsValid(BytesOf(cTestDataIsValid[i].Input)),
                IntToStr(i) + ': Failure on ' + string(cTestDataIsValid[i].Input));
  end;

  // Chars outside the range 32..$7F need to be hex encoded e.g. \X80
  SetLength(b, 1);
  b[0] := $80;
  CheckEquals(false, TFormat_ESCAPE.IsValid(b), 'Failure on: #$80 ');
end;

procedure TestTFormat_ESCAPE.TestIsValidTypeless;
var
  i     : Integer;
  Bytes : TBytes;
begin
  SetLength(Bytes, 0);
  CheckEquals(true, TFormat_ESCAPE.IsValid(Bytes, 0),'Failure on empty string ');

  // check all chars in allowed range
  for i := 32 to 127 do
  begin
    // skip backslash
    if i = $5C then
      Continue;

    {$IF CompilerVersion >= 24.0}
    CheckEquals(true, TFormat_ESCAPE.IsValid(RawByteString(chr(i))[low(RawByteString)], 1),
                'Failure on ' + chr(i) + ' ');
    {$ELSE}
    CheckEquals(true, TFormat_ESCAPE.IsValid(RawByteString(chr(i))[1], 1),
                'Failure on ' + chr(i) + ' ');
    {$IFEND}
  end;

  // check hex chars
  for i := 128 to 255 do
  begin
    Bytes := BytesOf('\X' + IntToHex(i, 2));
    CheckEquals(true, TFormat_ESCAPE.IsValid(Bytes[0], length(Bytes)),
                IntToStr(i) + ': Failure on \X' + IntToHex(i, 2));
  end;

  // check hex chars
  for i := 0 to 31 do
  begin
    Bytes := BytesOf('\X' + IntToHex(i, 2));
    CheckEquals(true, TFormat_ESCAPE.IsValid(Bytes[0], length(Bytes)),
                IntToStr(i) + ': Failure on \X' + IntToHex(i, 2));
  end;

  for i := Low(cTestDataIsValid) to High(cTestDataIsValid) do
  begin
    Bytes := BytesOf(cTestDataIsValid[i].Input);
    CheckEquals(cTestDataIsValid[i].Result,
                TFormat_ESCAPE.IsValid(Bytes[0], length(Bytes)),
                IntToStr(i) + ': Failure on ' + string(cTestDataIsValid[i].Input));
  end;

  // Chars outside the range 32..$7F need to be hex encoded e.g. \X80
  SetLength(Bytes, 1);
  Bytes[0] := $80;
  CheckEquals(false, TFormat_ESCAPE.IsValid(Bytes[0], 1), 'Failure on: #$80 ');
end;

{ TFormatTestsBase }

procedure TFormatTestsBase.DoTestEncodeDecode(EncodeDecodeProc: TEncodeDecodeProc;
                                              TestData: array of TestRecRawByteString);
var
  i       : Integer;
  SrcBuf,
  DestBuf : TBytes;
begin
  for i := Low(TestData) to High(TestData) do
  begin
    SrcBuf := BytesOf(RawByteString(TestData[i].Input));
    DestBuf := EncodeDecodeProc(SrcBuf);

    CheckEquals(TestData[i].Output,
                BytesToRawString(DestBuf));
  end;
end;

procedure TFormatTestsBase.DoTestEncodeDecodeRawByteString(EncodeDecodeProc: TEncodeDecodeProcRawByteString;
                                                           TestData: array of TestRecRawByteString);
var
  i      : Integer;
  result : RawByteString;
begin
  for i := Low(TestData) to High(TestData) do
  begin
    result := EncodeDecodeProc(TestData[i].Input);

    CheckEquals(TestData[i].Output, result);
  end;
end;

procedure TFormatTestsBase.DoTestEncodeDecodeTypeless(EncodeDecodeProc: TEncodeDecodeProcTypeless;
                                                      TestData: array of TestRecRawByteString);
var
  i      : Integer;
  result : RawByteString;
  pdata  : PByte;
  len    : Integer;
begin
  for i := Low(TestData) to High(TestData) do
  begin
    if length(TestData[i].Input) > 0 then
    begin
      {$IF CompilerVersion >= 24.0}
      pdata := @TestData[i].Input[low(TestData[i].Input)];

      len := length(TestData[i].Input) * SizeOf(TestData[i].Input[low(TestData[i].Input)]);
      {$ELSE}
      pdata := @TestData[i].Input[1];

      len := length(TestData[i].Input) * SizeOf(TestData[i].Input[1]);
      {$IFEND}
    end
    else
    begin
      pdata := nil;
      len   := 0;
    end;

    result := EncodeDecodeProc(pdata^, len);

    CheckEquals(TestData[i].Output, result);
  end;
end;

{ TestTFormat_BigEndian16 }

procedure TestTFormat_BigEndian16.SetUp;
begin
  FFormat_BigEndian16 := TFormat_BigEndian16.Create;
end;

procedure TestTFormat_BigEndian16.TearDown;
begin
  FFormat_BigEndian16.Free;
  FFormat_BigEndian16 := nil;
end;

procedure TestTFormat_BigEndian16.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_BigEndian16.ClassByName('TFormat_BigEndian16');
  CheckEquals(TFormat_BigEndian16, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_BigEndian16.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_BigEndian16.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian16.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_BigEndian16.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian16.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_BigEndian16.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian16.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_BigEndian16.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian16.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_BigEndian16.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian16.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_BigEndian16.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian16.TestIdentity;
begin
  CheckEquals($957DD064, FFormat_BigEndian16.Identity);
end;

procedure TestTFormat_BigEndian16.TestIsValidRawByteString;
begin
  CheckEquals(true, TFormat_BigEndian16.IsValid(RawByteString('')),'Failure on empty string');
  CheckEquals(false, TFormat_BigEndian16.IsValid(RawByteString('1')),'Failure on odd length string');
  CheckEquals(true, TFormat_BigEndian16.IsValid(RawByteString('12')),'Failure on 2-byte string');
  CheckEquals(false, TFormat_BigEndian16.IsValid(RawByteString('123')),'Failure on 1-byte string');
  CheckEquals(true, TFormat_BigEndian16.IsValid(RawByteString('1234')),'Failure on 4-byte string');
  CheckEquals(true, TFormat_BigEndian16.IsValid(RawByteString('1234abCdeFghijkl')),'Failure on 16-byte string');
end;

procedure TestTFormat_BigEndian16.TestIsValidTBytes;
begin
  CheckEquals(true, TFormat_BigEndian16.IsValid(BytesOf(RawByteString(''))),'Failure on empty string ');

  CheckEquals(false, TFormat_BigEndian16.IsValid(BytesOf(RawByteString('1'))),'Failure on 1-byte string');
  CheckEquals(true, TFormat_BigEndian16.IsValid(BytesOf(RawByteString('12'))),'Failure on 2-byte string');
  CheckEquals(false, TFormat_BigEndian16.IsValid(BytesOf(RawByteString('123'))),'Failure on 3-byte string');
  CheckEquals(true, TFormat_BigEndian16.IsValid(BytesOf(RawByteString('1234'))),'Failure on 4-byte string');
  CheckEquals(true, TFormat_BigEndian16.IsValid(BytesOf(RawByteString('1234abCdeFghijkl'))),'Failure on 16-byte string');
end;

procedure TestTFormat_BigEndian16.TestIsValidTypeless;
var
  Bytes : TBytes;
begin
  SetLength(Bytes, 0);
  CheckEquals(true, TFormat_BigEndian16.IsValid(Bytes, 0),'Failure on empty data');

  Bytes := TBytes.Create(1);
  CheckEquals(false, TFormat_BigEndian16.IsValid(Bytes, length(Bytes)),'Failure on 1-byte data');

  Bytes := TBytes.Create(254, 255);
  CheckEquals(true, TFormat_BigEndian16.IsValid(Bytes, length(Bytes)),'Failure on 2-byte data');

  Bytes := TBytes.Create(1, 2, 3);
  CheckEquals(false, TFormat_BigEndian16.IsValid(Bytes, length(Bytes)),'Failure on 3-byte data');

  Bytes := TBytes.Create(1, 2, 3, 4);
  CheckEquals(true, TFormat_BigEndian16.IsValid(Bytes, length(Bytes)),'Failure on 4-byte data');

  Bytes := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
  CheckEquals(true, TFormat_BigEndian16.IsValid(Bytes, length(Bytes)),'Failure on 16-byte data');
end;

{ TestTFormat_BigEndian32 }

procedure TestTFormat_BigEndian32.SetUp;
begin
  FFormat_BigEndian32 := TFormat_BigEndian32.Create;
end;

procedure TestTFormat_BigEndian32.TearDown;
begin
  FFormat_BigEndian32.Free;
  FFormat_BigEndian32 := nil;
end;

procedure TestTFormat_BigEndian32.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_BigEndian32.ClassByName('TFormat_BigEndian32');
  CheckEquals(TFormat_BigEndian32, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_BigEndian32.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_BigEndian32.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian32.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_BigEndian32.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian32.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_BigEndian32.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian32.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_BigEndian32.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian32.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_BigEndian32.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian32.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_BigEndian32.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian32.TestIdentity;
begin
  CheckEquals($A02676FF, FFormat_BigEndian32.Identity);
end;

procedure TestTFormat_BigEndian32.TestIsValidRawByteString;
begin
  CheckEquals(true, TFormat_BigEndian32.IsValid(RawByteString('')),'Failure on empty string');
  CheckEquals(false, TFormat_BigEndian32.IsValid(RawByteString('1')),'Failure on odd length string');
  CheckEquals(false, TFormat_BigEndian32.IsValid(RawByteString('12')),'Failure on 2-byte string');
  CheckEquals(false, TFormat_BigEndian32.IsValid(RawByteString('123')),'Failure on 1-byte string');
  CheckEquals(true, TFormat_BigEndian32.IsValid(RawByteString('1234')),'Failure on 4-byte string');
  CheckEquals(true, TFormat_BigEndian32.IsValid(RawByteString('1234abCdeFghijkl')),'Failure on 16-byte string');
end;

procedure TestTFormat_BigEndian32.TestIsValidTBytes;
begin
  CheckEquals(true, TFormat_BigEndian32.IsValid(BytesOf(RawByteString(''))),'Failure on empty string ');

  CheckEquals(false, TFormat_BigEndian32.IsValid(BytesOf(RawByteString('1'))),'Failure on 1-byte string');
  CheckEquals(false, TFormat_BigEndian32.IsValid(BytesOf(RawByteString('12'))),'Failure on 2-byte string');
  CheckEquals(false, TFormat_BigEndian32.IsValid(BytesOf(RawByteString('123'))),'Failure on 3-byte string');
  CheckEquals(true, TFormat_BigEndian32.IsValid(BytesOf(RawByteString('1234'))),'Failure on 4-byte string');
  CheckEquals(true, TFormat_BigEndian32.IsValid(BytesOf(RawByteString('1234abCdeFghijkl'))),'Failure on 16-byte string');
end;

procedure TestTFormat_BigEndian32.TestIsValidTypeless;
var
  Bytes : TBytes;
begin
  SetLength(Bytes, 0);
  CheckEquals(true, TFormat_BigEndian32.IsValid(Bytes, 0),'Failure on empty data');

  Bytes := TBytes.Create(1);
  CheckEquals(false, TFormat_BigEndian32.IsValid(Bytes, length(Bytes)),'Failure on 1-byte data');

  Bytes := TBytes.Create(254, 255);
  CheckEquals(false, TFormat_BigEndian32.IsValid(Bytes, length(Bytes)),'Failure on 2-byte data');

  Bytes := TBytes.Create(1, 2, 3);
  CheckEquals(false, TFormat_BigEndian32.IsValid(Bytes, length(Bytes)),'Failure on 3-byte data');

  Bytes := TBytes.Create(1, 2, 3, 4);
  CheckEquals(true, TFormat_BigEndian32.IsValid(Bytes, length(Bytes)),'Failure on 4-byte data');

  Bytes := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
  CheckEquals(true, TFormat_BigEndian32.IsValid(Bytes, length(Bytes)),'Failure on 16-byte data');
end;

{ TestTFormat_BigEndian64 }

procedure TestTFormat_BigEndian64.SetUp;
begin
  FFormat_BigEndian64 := TFormat_BigEndian64.Create;
end;

procedure TestTFormat_BigEndian64.TearDown;
begin
  FFormat_BigEndian64.Free;
  FFormat_BigEndian64 := nil;
end;

procedure TestTFormat_BigEndian64.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_BigEndian64.ClassByName('TFormat_BigEndian64');
  CheckEquals(TFormat_BigEndian64, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_BigEndian64.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_BigEndian64.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian64.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_BigEndian64.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian64.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_BigEndian64.Decode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian64.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_BigEndian64.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian64.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_BigEndian64.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian64.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_BigEndian64.Encode, cTestDataEncode);
end;

procedure TestTFormat_BigEndian64.TestIdentity;
begin
  CheckEquals($3432278F, FFormat_BigEndian64.Identity);
end;

procedure TestTFormat_BigEndian64.TestIsValidRawByteString;
begin
  CheckEquals(true, TFormat_BigEndian64.IsValid(RawByteString('')),'Failure on empty string');
  CheckEquals(false, TFormat_BigEndian64.IsValid(RawByteString('1')),'Failure on odd length string');
  CheckEquals(false, TFormat_BigEndian64.IsValid(RawByteString('12')),'Failure on 2-byte string');
  CheckEquals(false, TFormat_BigEndian64.IsValid(RawByteString('123')),'Failure on 1-byte string');
  CheckEquals(false, TFormat_BigEndian64.IsValid(RawByteString('1234')),'Failure on 4-byte string');
  CheckEquals(true, TFormat_BigEndian64.IsValid(RawByteString('1234abCd')),'Failure on 8-byte string');
  CheckEquals(true, TFormat_BigEndian64.IsValid(RawByteString('1234abCdeFghijkl')),'Failure on 16-byte string');
end;

procedure TestTFormat_BigEndian64.TestIsValidTBytes;
begin
  CheckEquals(true, TFormat_BigEndian64.IsValid(BytesOf(RawByteString(''))),'Failure on empty string ');

  CheckEquals(false, TFormat_BigEndian64.IsValid(BytesOf(RawByteString('1'))),'Failure on 1-byte string');
  CheckEquals(false, TFormat_BigEndian64.IsValid(BytesOf(RawByteString('12'))),'Failure on 2-byte string');
  CheckEquals(false, TFormat_BigEndian64.IsValid(BytesOf(RawByteString('123'))),'Failure on 3-byte string');
  CheckEquals(false, TFormat_BigEndian64.IsValid(BytesOf(RawByteString('1234'))),'Failure on 4-byte string');
  CheckEquals(true, TFormat_BigEndian64.IsValid(BytesOf(RawByteString('1234abCd'))),'Failure on 8-byte string');
  CheckEquals(true, TFormat_BigEndian64.IsValid(BytesOf(RawByteString('1234abCdeFghijkl'))),'Failure on 16-byte string');
end;

procedure TestTFormat_BigEndian64.TestIsValidTypeless;
var
  Bytes : TBytes;
begin
  SetLength(Bytes, 0);
  CheckEquals(true, TFormat_BigEndian64.IsValid(Bytes, 0),'Failure on empty data');

  Bytes := TBytes.Create(1);
  CheckEquals(false, TFormat_BigEndian64.IsValid(Bytes, length(Bytes)),'Failure on 1-byte data');

  Bytes := TBytes.Create(254, 255);
  CheckEquals(false, TFormat_BigEndian64.IsValid(Bytes, length(Bytes)),'Failure on 2-byte data');

  Bytes := TBytes.Create(1, 2, 3);
  CheckEquals(false, TFormat_BigEndian64.IsValid(Bytes, length(Bytes)),'Failure on 3-byte data');

  Bytes := TBytes.Create(1, 2, 3, 4);
  CheckEquals(false, TFormat_BigEndian64.IsValid(Bytes, length(Bytes)),'Failure on 4-byte data');

  Bytes := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  CheckEquals(true, TFormat_BigEndian64.IsValid(Bytes, length(Bytes)),'Failure on 8-byte data');

  Bytes := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
  CheckEquals(true, TFormat_BigEndian64.IsValid(Bytes, length(Bytes)),'Failure on 16-byte data');
end;

{ TestTFormat_Base32 }

procedure TestTFormat_Base32.DoTestDecodeException;
begin
  FFormat_Base32.Decode('A'#47);
end;

procedure TestTFormat_Base32.SetUp;
begin
  FFormat_Base32 := TFormat_Base32.Create;
end;

procedure TestTFormat_Base32.TearDown;
begin
  FFormat_Base32.Free;
  FFormat_Base32 := nil;
end;

procedure TestTFormat_Base32.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_Base32.ClassByName('TFormat_Base32');
  CheckEquals(TFormat_Base32, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_Base32.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_Base32.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base32.TestDecodeException;
begin
  CheckException(DoTestDecodeException, EDECFormatException);
end;

procedure TestTFormat_Base32.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Base32.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base32.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Base32.Decode, cTestDataDecode);
end;

procedure TestTFormat_Base32.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_Base32.Encode, cTestDataEncode);
end;

procedure TestTFormat_Base32.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_Base32.Encode, cTestDataEncode);
end;

procedure TestTFormat_Base32.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_Base32.Encode, cTestDataEncode);
end;

procedure TestTFormat_Base32.TestIdentity;
begin
  CheckEquals($C60FF021, FFormat_Base32.Identity);
end;

procedure TestTFormat_Base32.TestIsValidRawByteString;
var
  i : Integer;
begin
  CheckEquals(true, TFormat_Base64.IsValid(BytesOf('')));

  CheckEquals(true, TFormat_Base64.IsValid(
    BytesOf('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')));
  CheckEquals(false, TFormat_Base64.IsValid(BytesOf('ABC"')));
  CheckEquals(true, TFormat_Base64.IsValid(BytesOf('6')));

  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    CheckEquals(true, TFormat_Base64.IsValid(RawByteString(cTestDataDecode[i].Input)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

procedure TestTFormat_Base32.TestIsValidTBytes;
const
  Data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=';
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_Base32.IsValid(SrcBuf));

  SetLength(SrcBuf, 1);
  for i := 0 to 255 do
  begin
    SrcBuf[0] := i;

    if (pos(chr(i), Data) > 0) then
      CheckEquals(true, TFormat_Base32.IsValid(SrcBuf),
                  'Failure at char: ' + Chr(i) + ' ')
    else
      CheckEquals(false, TFormat_Base32.IsValid(SrcBuf),
                  'Failure at char nr: ' + IntToHex(i, 8) + ' ');
  end;

  SrcBuf := BytesOf('ABC"');
  CheckEquals(false, TFormat_Base32.IsValid(SrcBuf), 'Data: ABC" ');

  SrcBuf := BytesOf(cTestDataDecode[3].Input);
  CheckEquals(true, TFormat_Base32.IsValid(SrcBuf),
              'Data: ' + string(cTestDataDecode[3].Input));

  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    SrcBuf := BytesOf(RawByteString(cTestDataDecode[i].Input));
    CheckEquals(true, TFormat_Base32.IsValid(SrcBuf),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

procedure TestTFormat_Base32.TestIsValidTypeless;
const
  Data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=';
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  SrcBuf := BytesOf(RawByteString(''));
  CheckEquals(true, TFormat_Base32.IsValid(SrcBuf, 0));

  SetLength(SrcBuf, 1);
  for i := 0 to 255 do
  begin
    SrcBuf[0] := i;

    if (pos(chr(i), Data) > 0) then
      CheckEquals(true, TFormat_Base32.IsValid(SrcBuf[0], length(SrcBuf)),
                  'Failure at char: ' + Chr(i) + ' ')
    else
      CheckEquals(false, TFormat_Base32.IsValid(SrcBuf[0], length(SrcBuf)),
                  'Failure at char nr: ' + IntToHex(i, 8) + ' ');
  end;


  SrcBuf := BytesOf('ABC"');
  CheckEquals(false, TFormat_Base32.IsValid(SrcBuf[0], length(SrcBuf)), 'Data: ABC" ');

  SrcBuf := BytesOf(cTestDataDecode[3].Input);
  CheckEquals(true, TFormat_Base32.IsValid(SrcBuf[0], length(SrcBuf)),
              'Data: ' + string(cTestDataDecode[3].Input));

  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    SrcBuf := BytesOf(RawByteString(cTestDataDecode[i].Input));
    CheckEquals(true, TFormat_Base32.IsValid(SrcBuf[0], length(SrcBuf)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

{ TestTFormat_BCryptBSD }

procedure TestTFormat_BCryptBSD.SetUp;
begin
  FFormat_BCryptBSD := TFormat_BCryptBSD.Create;
end;

procedure TestTFormat_BCryptBSD.TearDown;
begin
  FFormat_BCryptBSD.Free;
  FFormat_BCryptBSD := nil;
end;

procedure TestTFormat_BCryptBSD.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_BCryptBSD.ClassByName('TFormat_BCryptBSD');
  CheckEquals(TFormat_BCryptBSD, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_BCryptBSD.TestDecodeBytes;
begin
  DoTestEncodeDecode(FFormat_BCryptBSD.Decode, cTestDataDecode);
end;

procedure TestTFormat_BCryptBSD.TestDecodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_BCryptBSD.Decode, cTestDataDecode);
end;

procedure TestTFormat_BCryptBSD.TestDecodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_BCryptBSD.Decode, cTestDataDecode);
end;

procedure TestTFormat_BCryptBSD.TestEncodeBytes;
begin
  DoTestEncodeDecode(FFormat_BCryptBSD.Encode, cTestDataEncode);
end;

procedure TestTFormat_BCryptBSD.TestEncodeRawByteString;
begin
  DoTestEncodeDecodeRawByteString(FFormat_BCryptBSD.Encode, cTestDataEncode);
end;

procedure TestTFormat_BCryptBSD.TestEncodeTypeless;
begin
  DoTestEncodeDecodeTypeless(FFormat_BCryptBSD.Encode, cTestDataEncode);
end;

procedure TestTFormat_BCryptBSD.TestIdentity;
begin
  CheckEquals($D2A9C077, FFormat_BCryptBSD.Identity);
end;

procedure TestTFormat_BCryptBSD.TestIsValidRawByteString;
var
  i     : Integer;
begin
  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    CheckEquals(true, TFormat_BCryptBSD.IsValid(cTestDataDecode[i].Input),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

procedure TestTFormat_BCryptBSD.TestIsValidTBytes;
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    SrcBuf := BytesOf(RawByteString(cTestDataDecode[i].Input));
    CheckEquals(true, TFormat_BCryptBSD.IsValid(SrcBuf),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

procedure TestTFormat_BCryptBSD.TestIsValidTypeless;
var
  SrcBuf: TBytes;
  i     : Integer;
begin
  for i := low(cTestDataDecode) to high(cTestDataDecode) do
  begin
    // skip empty test data
    if (cTestDataDecode[i].Input = '') then
      Continue;

    SrcBuf := BytesOf(RawByteString(cTestDataDecode[i].Input));
    CheckEquals(true, TFormat_BCryptBSD.IsValid(SrcBuf[0], length(SrcBuf)),
                'Failure on ' + string(cTestDataDecode[i].Input) + ' ');
  end;
end;

{ TestTFormat_UTF8 }

procedure TestTFormat_UTF8.SetUp;
begin
  FFormat_UTF8 := TFormat_UTF8.Create;
end;

procedure TestTFormat_UTF8.TearDown;
begin
  FreeAndNil(FFormat_UTF8);
end;

procedure TestTFormat_UTF8.TestClassByName;
var
  ReturnValue : TDECFormatClass;
begin
  ReturnValue := FFormat_UTF8.ClassByName('TFormat_UTF8');
  CheckEquals(TFormat_UTF8, ReturnValue, 'Class is not registered');
end;

procedure TestTFormat_UTF8.TestEncodeBytes;
var
  i: integer;
begin
  for i := 1 to length(cTestDataEncode) do
    DoTestEncodeDecode(FFormat_UTF8.Encode, cTestDataEncode[i]);
end;

procedure TestTFormat_UTF8.TestEncodeRawByteString;
var
  i: integer;
begin
  for i := 1 to length(cTestDataEncode) do
    DoTestEncodeDecodeRawByteString(FFormat_UTF8.Encode, cTestDataEncode[i]);
end;

procedure TestTFormat_UTF8.TestEncodeTypeless;
var
  i: integer;
begin
  for i := 1 to length(cTestDataEncode) do
    DoTestEncodeDecodeTypeless(FFormat_UTF8.Encode, cTestDataEncode[i]);
end;

procedure TestTFormat_UTF8.TestDecodeBytes;
var
  i: integer;
begin
  for i := 1 to length(cTestDataDecode) do
    DoTestEncodeDecode(FFormat_UTF8.Decode, cTestDataDecode[i]);
end;

procedure TestTFormat_UTF8.TestDecodeRawByteString;
var
  i: integer;
begin
  for i := 1 to length(cTestDataDecode) do
    DoTestEncodeDecodeRawByteString(FFormat_UTF8.Decode, cTestDataDecode[i]);
end;

procedure TestTFormat_UTF8.TestDecodeTypeless;
var
  i: integer;
begin
  for i := 1 to length(cTestDataDecode) do
    DoTestEncodeDecodeTypeless(FFormat_UTF8.Decode, cTestDataDecode[i]);
end;

procedure TestTFormat_UTF8.TestIdentity;
begin
  CheckEquals($56C1D72, FFormat_UTF8.Identity);
end;

procedure TestTFormat_UTF8.TestIsValidRawByteString;
var
  Bytes : TBytes;
begin
  SetLength(Bytes, 0);
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on empty data');

  Bytes := TBytes.Create(1);
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on 1-byte data');

  Bytes := TBytes.Create($20);
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on 1-byte data-1');

  Bytes := TBytes.Create(195, 164);  // ä
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on 2-byte data');

  Bytes := TBytes.Create(226, 130, 172); // €
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on 3-byte data');

  Bytes := TBytes.Create(240, 159, 152, 128); // 😀
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on 4-byte data');

  Bytes := TBytes.Create(130); // is a continuation byte
//  CheckEquals(false, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes), true),'Failure on continuation byte');
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on continuation byte');

  Bytes := TBytes.Create(255); // 255 is not a valid UTF-8 start byte
//  CheckEquals(false, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes), true),'Failure on start byte');
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on start byte');

  Bytes := TBytes.Create(240, 159); // The start byte 240 expects three continuation bytes, but there is only one.
//  CheckEquals(false, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes), true),'Failure on continuation bytes.');
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on continuation bytes.');

  Bytes := TBytes.Create(192, 128); // This sequence encodes the ASCII value 0 using 2 bytes, which is forbidden in UTF-8
//  CheckEquals(false, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes), true),'Failure on continuation bytes.');
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Failure on continuation bytes.');

  Bytes := TBytes.Create(129, 128, 128);
//  CheckEquals(false, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes), true),'Continuation bytes can only follow valid start bytes');
  CheckEquals(true, TFormat_UTF8.IsValid(DECUtil.BytesToRawString(Bytes)),'Continuation bytes can only follow valid start bytes');
end;

procedure TestTFormat_UTF8.TestIsValidTBytes;
var
  Bytes : TBytes;
begin
  SetLength(Bytes, 0);
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on empty data');

  Bytes := TBytes.Create(1);
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on 1-byte data');

  Bytes := TBytes.Create($20);
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on 1-byte data-1');

  Bytes := TBytes.Create(195, 164);  // ä
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on 2-byte data');

  Bytes := TBytes.Create(226, 130, 172); // €
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on 3-byte data');

  Bytes := TBytes.Create(240, 159, 152, 128); // 😀
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on 4-byte data');

  Bytes := TBytes.Create(130); // is a continuation byte
//  CheckEquals(false, TFormat_UTF8.IsValid(Bytes, true),'Failure on continuation byte');
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on continuation byte');

  Bytes := TBytes.Create(255); // 255 is not a valid UTF-8 start byte
//  CheckEquals(false, TFormat_UTF8.IsValid(Bytes, true),'Failure on start byte');
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on start byte');

  Bytes := TBytes.Create(240, 159); // The start byte 240 expects three continuation bytes, but there is only one.
//  CheckEquals(false, TFormat_UTF8.IsValid(Bytes, true),'Failure on continuation bytes.');
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on continuation bytes.');

  Bytes := TBytes.Create(192, 128); // This sequence encodes the ASCII value 0 using 2 bytes, which is forbidden in UTF-8
//  CheckEquals(false, TFormat_UTF8.IsValid(Bytes, true),'Failure on continuation bytes.');
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Failure on continuation bytes.');

  Bytes := TBytes.Create(129, 128, 128);
//  CheckEquals(false, TFormat_UTF8.IsValid(Bytes, true),'Continuation bytes can only follow valid start bytes');
  CheckEquals(true, TFormat_UTF8.IsValid(Bytes),'Continuation bytes can only follow valid start bytes');
end;

procedure TestTFormat_UTF8.TestIsValidTypeless;
var
  Bytes : TBytes;
  p: pointer;
begin
  p := nil;
  CheckEquals(true, TFormat_UTF8.IsValid(p, 0),'Failure on empty data');

  Bytes := TBytes.Create(1);
  p := @Bytes[0];
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 1),'Failure on 1-byte data');

  Bytes := TBytes.Create($20);
  p := @Bytes[0];
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 1),'Failure on 1-byte data-1');

  Bytes := TBytes.Create(195, 164);  // ä
  p := @Bytes[0];
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 2),'Failure on 2-byte data');

  Bytes := TBytes.Create(226, 130, 172); // €
  p := @Bytes[0];
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 3),'Failure on 3-byte data');

  Bytes := TBytes.Create(240, 159, 152, 128); // 😀
  p := @Bytes[0];
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 4),'Failure on 4-byte data');

  Bytes := TBytes.Create(130); // is a continuation byte
  p := @Bytes[0];
//  CheckEquals(false, TFormat_UTF8.IsValid(p^, 1, true),'Failure on continuation byte');
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 1),'Failure on continuation byte');

  Bytes := TBytes.Create(255); // 255 is not a valid UTF-8 start byte
  p := @Bytes[0];
//  CheckEquals(false, TFormat_UTF8.IsValid(p^, 1, true),'Failure on start byte');
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 1),'Failure on start byte');

  Bytes := TBytes.Create(240, 159); // The start byte 240 expects three continuation bytes, but there is only one.
  p := @Bytes[0];
//  CheckEquals(false, TFormat_UTF8.IsValid(p^, 2, true),'Failure on continuation bytes.');
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 2),'Failure on continuation bytes.');

  Bytes := TBytes.Create(192, 128); // This sequence encodes the ASCII value 0 using 2 bytes, which is forbidden in UTF-8
  p := @Bytes[0];
//  CheckEquals(false, TFormat_UTF8.IsValid(p^, 2, true),'Failure on continuation bytes.');
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 2),'Failure on continuation bytes.');

  Bytes := TBytes.Create(129, 128, 128);
  p := @Bytes[0];
//  CheckEquals(false, TFormat_UTF8.IsValid(p^, 3, true),'Continuation bytes can only follow valid start bytes');
  CheckEquals(true, TFormat_UTF8.IsValid(p^, 3),'Continuation bytes can only follow valid start bytes');
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
//  TDUnitX.RegisterTestFixture(TestTFormat);
  TDUnitX.RegisterTestFixture(TestTFormat_HEX);
  TDUnitX.RegisterTestFixture(TestTFormat_HEXL);
  TDUnitX.RegisterTestFixture(TestTFormat_DECMIME32);
  TDUnitX.RegisterTestFixture(TestTFormat_Base32);
  TDUnitX.RegisterTestFixture(TestTFormat_Base64);
  TDUnitX.RegisterTestFixture(TestTFormat_Radix64);
  TDUnitX.RegisterTestFixture(TestTFormat_BCryptBSD);
  TDUnitX.RegisterTestFixture(TestTFormat_UU);
  TDUnitX.RegisterTestFixture(TestTFormat_XX);
  TDUnitX.RegisterTestFixture(TestTFormat_ESCAPE);
  TDUnitX.RegisterTestFixture(TestTFormat_BigEndian16);
  TDUnitX.RegisterTestFixture(TestTFormat_BigEndian32);
  TDUnitX.RegisterTestFixture(TestTFormat_BigEndian64);
  TDUnitX.RegisterTestFixture(TestTFormat_UTF16);
  {$ELSE}
  RegisterTests('DECFormat', [//TestTFormat,
                              TestTFormat_HEX.Suite,
                              TestTFormat_HEXL.Suite,
                              TestTFormat_DECMIME32.Suite,
                              TestTFormat_Base32.Suite,
                              TestTFormat_Base64.Suite,
                              TestTFormat_Radix64.Suite,
                              TestTFormat_BCryptBSD.Suite,
                              TestTFormat_UU.Suite,
                              TestTFormat_XX.Suite,
                              TestTFormat_ESCAPE.Suite,
                              TestTFormat_BigEndian16.Suite,
                              TestTFormat_BigEndian32.Suite,
                              TestTFormat_UTF8.Suite,
                              TestTFormat_UTF16.Suite]);
  {$ENDIF}

finalization
end.


