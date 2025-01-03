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
unit TestDECCipherPaddings;

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}

interface

uses
  System.SysUtils, System.Classes, Generics.Collections,
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  DECCIpherPaddings;

type
  // Test methods for class TPKCS7Padding
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECPKCS7Padding = class(TTestCase)
  strict private
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
//    procedure TestClassByName;
//    procedure TestClassByIdentity;
//    procedure TestGetClassList;
  end;

  // Test methods for class TANSI_X9_23Padding
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTANSI_X9_23Padding = class(TTestCase)
  strict private
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
  end;


//pmANSI_X9_23 {, pmISO10126, pmISO7816

implementation

{ TestTDECPKCS7Padding }

procedure TestTDECPKCS7Padding.SetUp;
begin
  inherited;

end;

procedure TestTDECPKCS7Padding.TearDown;
begin
  inherited;

end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestTDECPKCS7Padding);
  TDUnitX.RegisterTestFixture(TestTANSI_X9_23Padding);
  {$ELSE}
  RegisterTests('DECCipherPaddings', [TestTDECPKCS7Padding.Suite, TestTANSI_X9_23Padding.Suite]);
  {$ENDIF}
end.
