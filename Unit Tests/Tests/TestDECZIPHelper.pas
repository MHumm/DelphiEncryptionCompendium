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
unit TestDECZIPHelper;

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
  DECUtil;

type
  /// <summary>
  ///   Test cases for the various helper functions
  /// </summary>
  TestZIPHelpers = class(TTestCase)
  strict private
    /// <summary>
    ///   Perform a signle algorithm create test
    /// </summary>
    /// <param name="AlgorithmID">
    ///   ID of the algorithm instance to create
    /// </param>
    /// <param name="Name">
    ///   Short class name of the instance to be created, must match to pass
    /// </param>
    procedure DoTestCreateZIPCryptoAlgorithmInstance(AlgorithmID: UInt16;
                                                     const Name : string);
    /// <summary>
    ///   Test for the "unknown" algorithm ID as parameter
    /// </summary>
    procedure DoTestCreateZIPUnknownCryptoAlgorithmException;
    /// <summary>
    ///   Test for an arbitrary unknown algorithm ID as parameter
    /// </summary>
    procedure DoTestCreateZIPUnknCryptoAlgorithmException;
  published
    procedure TestCreateZIPCryptoAlgorithmInstance;
    procedure TestCreateZIPUnknownCryptoAlgorithmInstanceException;
    procedure TestCreateZIPUnknCryptoAlgorithmInstanceException;
  end;

implementation

uses
  DECTypes,
  DECCipherFormats,
  DECZIPHelper;

procedure TestZIPHelpers.DoTestCreateZIPUnknCryptoAlgorithmException;
var
  Instance : TDECFormattedCipher;
begin
  Instance := CreateZIPCryptoAlgorithmInstance($1000);
  Instance.Free; // Should not be reached but suppresses compiler warning
end;

procedure TestZIPHelpers.DoTestCreateZIPUnknownCryptoAlgorithmException;
var
  Instance : TDECFormattedCipher;
begin
  Instance := CreateZIPCryptoAlgorithmInstance($FFFF);
  Instance.Free; // Should not be reached but suppresses compiler warning
end;

procedure TestZIPHelpers.DoTestCreateZIPCryptoAlgorithmInstance(AlgorithmID: UInt16;
                                                                const Name: string);
var
  Instance : TDECFormattedCipher;
begin
  Instance := CreateZIPCryptoAlgorithmInstance(AlgorithmID);
  try
    CheckEquals(Name, Instance.GetShortClassName);
  finally
    Instance.Free;
  end;
end;

procedure TestZIPHelpers.TestCreateZIPCryptoAlgorithmInstance;
begin
  DoTestCreateZIPCryptoAlgorithmInstance($6601, '1DES');
  DoTestCreateZIPCryptoAlgorithmInstance($6603, '3DES');
  DoTestCreateZIPCryptoAlgorithmInstance($6609, '2DES');
  DoTestCreateZIPCryptoAlgorithmInstance($660E, 'AES128');
  DoTestCreateZIPCryptoAlgorithmInstance($660F, 'AES192');
  DoTestCreateZIPCryptoAlgorithmInstance($6610, 'AES256');
  DoTestCreateZIPCryptoAlgorithmInstance($6702, 'RC2');
  DoTestCreateZIPCryptoAlgorithmInstance($6720, 'Blowfish');
  DoTestCreateZIPCryptoAlgorithmInstance($6721, 'Twofish');
  DoTestCreateZIPCryptoAlgorithmInstance($6801, 'RC4');

//    $6602 : Result := TCipher_RC2.Create; // (version needed to extract < 5.2)
//                                          // This has to do with a faulty RC2
//                                          // implementation in XP SP1 and earlier
//                                          // Unsupported as we do not know the
//                                          // details of the fault
end;

procedure TestZIPHelpers.TestCreateZIPUnknCryptoAlgorithmInstanceException;
begin
  CheckException(DoTestCreateZIPUnknCryptoAlgorithmException, EDECClassNotRegisteredException);
end;

procedure TestZIPHelpers.TestCreateZIPUnknownCryptoAlgorithmInstanceException;
begin
  CheckException(DoTestCreateZIPUnknownCryptoAlgorithmException, EDECClassNotRegisteredException);
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(TestZIPHelpers);
  {$ELSE}
  RegisterTest('DECZIPHelper', TestZIPHelpers.Suite);
  {$ENDIF}
end.
