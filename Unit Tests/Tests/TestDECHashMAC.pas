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
unit TestDECHashMAC;

interface

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}
{$INCLUDE ..\..\Source\DECOptions.inc}

uses
  System.Classes, System.SysUtils, Generics.Collections,
  {$IFDEF DUnitX}
  DUnitX.TestFramework, DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  TestDECTestDataContainer, DECBaseClass, DECHash, DECHashBase;

type
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  /// <summary>
  ///   All test cases for the HMAC class methods.
  /// </summary>
  TestTHash_HMAC = class(TTestCase)
  strict protected
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestHMACBytes;
    procedure TestHMACRawByteString;
  end;

implementation

uses
  DECFormatBase, DECFormat;

{ TestTHash_HMAC }

procedure TestTHash_HMAC.SetUp;
begin
  inherited;

end;

procedure TestTHash_HMAC.TearDown;
begin
  inherited;

end;

procedure TestTHash_HMAC.TestHMACBytes;
var
  Res: TBytes;
  AAx80String: TBytes;
begin
  Res := THash_MD5.HMAC(BytesOf('key'), BytesOf('The quick brown fox jumps over the lazy dog'));
  CheckEquals('80070713463E7749B90C2DC24911E275', StringOf(ValidFormat(TFormat_HEX).Encode(Res)),
              'MD5 failure in The quick...');

  Res := THash_SHA1.HMAC(BytesOf('key'), BytesOf('The quick brown fox jumps over the lazy dog'));
  CheckEquals('DE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9', StringOf(ValidFormat(TFormat_HEX).Encode(Res)),
              'SHA1 failure in The quick...');

  Res := THash_SHA256.HMAC(BytesOf('key'), BytesOf('The quick brown fox jumps over the lazy dog'));
  CheckEquals('F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8',
              StringOf(ValidFormat(TFormat_HEX).Encode(Res)),
              'SHA256 failure in The quick...');
end;

procedure TestTHash_HMAC.TestHMACRawByteString;
var
  Res: TBytes;
  AAx80String: TBytes;
begin
  Res := THash_MD5.HMAC(RawByteString('key'), RawByteString('The quick brown fox jumps over the lazy dog'));
  CheckEquals('80070713463E7749B90C2DC24911E275', StringOf(ValidFormat(TFormat_HEX).Encode(Res)),
              'MD5 failure in The quick...');

  Res := THash_SHA1.HMAC(RawByteString('key'), RawByteString('The quick brown fox jumps over the lazy dog'));
  CheckEquals('DE7C9B85B8B78AA6BC8A7A36F70A90701C9DB4D9', StringOf(ValidFormat(TFormat_HEX).Encode(Res)),
              'SHA1 failure in The quick...');

  Res := THash_SHA256.HMAC(RawByteString('key'), RawByteString('The quick brown fox jumps over the lazy dog'));
  CheckEquals('F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8',
              StringOf(ValidFormat(TFormat_HEX).Encode(Res)),
              'SHA256 failure in The quick...');
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTHash_HMAC);
  {$ELSE}
  RegisterTests('DECHashHMAC', [TestTHash_HMAC.Suite]);
  {$ENDIF}
end.
