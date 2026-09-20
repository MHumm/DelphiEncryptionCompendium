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
///   Common definitions used by all authenticated cipher modes tests, if possible.
///   The file loading for the individual algorithms has to be implemented in the
///   individual test unit for the algorith, because NIST doesn't use a 100%
///   identical file format for CCM and GCM.
/// </summary>
unit AuthenticatedCiphersCommonTestData;

interface

uses
  Generics.Collections;

type
  /// <summary>
  ///   Test data for one single authenticated cipher test, all in HexL
  /// </summary>
  TSingleAuthenticatedTestData = record
    /// <summary>
    ///   Encryption/decryption key
    /// </summary>
    CryptKey   : RawByteString;
    /// <summary>
    ///   Initialization vecotr
    /// </summary>
    InitVector : RawByteString;
    /// <summary>
    ///   Plain Text: text to be encrypted, given in HexL
    /// </summary>
    PT         : RawByteString;
    /// <summary>
    ///   Additional Authenticated Data: the data which shall be authenticated
    ///   but not encrypted.
    /// </summary>
    AAD        : RawByteString;
    /// <summary>
    ///   Cipher Text: encrypted text, given in HexL
    /// </summary>
    CT         : RawByteString;
    /// <summary>
    ///   Calculated authenticated "tag" value
    /// </summary>
    TagResult  : RawByteString;
    /// <summary>
    ///   Used additional authenticated data for testing authentication failures.
    ///   Only filled when present in test data file.
    /// </summary>
    ModifiedAAD: RawByteString;
    /// <summary>
    ///   Used ciphertext data for testing authentication failures.
    ///   Only filled when present in test data file.
    /// </summary>
    ModifiedCT: RawByteString;

    /// <summary>
    ///   Sets all fields and array entries to default values
    /// </summary>
    procedure Clear;
  end;

  /// <summary>
  ///   Test data for one single GCM test
  /// </summary>
  TAuthenticatedCipherTestSetEntry = record
    /// <summary>
    ///   Length of the encryption/decryption key in bit, determines the
    ///   algorithm used in case of AES (AES128, AES192, AES256)
    /// </summary>
    Keylen : UInt16;
    /// <summary>
    ///   Length of the initialization vector in bit
    /// </summary>
    IVlen  : UInt16;
    /// <summary>
    ///   Length of the ? in bit
    /// </summary>
    PTlen  : UInt16;
    /// <summary>
    ///   Length of the ? in bit
    /// </summary>
    AADlen : UInt16;
    /// <summary>
    ///   Length of the "tag" resulting from the authentication part in bit
    /// </summary>
    Taglen : UInt16;

    /// <summary>
    ///   The test data files provided contains one test for the meta data
    ///   specified above. This array holds the test data.
    /// </summary>
    TestData : array of TSingleAuthenticatedTestData;

    /// <summary>
    ///   Sets all fields and array entries to default values
    /// </summary>
    procedure Clear;
  end;

  /// <summary>
  ///   List of loaded authentication cipher test vectors
  /// </summary>
  TAuthenticatedTestDataList = TList<TAuthenticatedCipherTestSetEntry>;

implementation

{ TSingleAuthenticatedTestData }

procedure TSingleAuthenticatedTestData.Clear;
begin
  CryptKey    := '';
  InitVector  := '';
  PT          := '';
  AAD         := '';
  CT          := '';
  TagResult   := '';
  ModifiedAAD := '';
  ModifiedCT  := '';
end;

{ TAuthenticatedCipherTestSetEntry }

procedure TAuthenticatedCipherTestSetEntry.Clear;
var
  i : Integer;
begin
  Keylen := 0;
  IVlen  := 0;
  PTlen  := 0;
  AADlen := 0;
  Taglen := 0;

  for i := Low(TestData) to High(TestData) do
    TestData[i].Clear;
end;

end.
