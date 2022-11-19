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
unit TestDECHash;

interface

// Needs to be included before any other statements
{$INCLUDE TestDefines.inc}
{$INCLUDE ..\..\Source\DECOptions.inc}

uses
  System.SysUtils, System.Classes, Generics.Collections,
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  TestDECTestDataContainer,
  DECTypes, DECBaseClass, DECHash, DECHashBase, DECHashAuthentication, DECUtil,
  DECFormatBase, DECHashBitBase;

type
  /// <summary>
  ///   Makes Increment8 method public for testing purposes as we fixed the ASM
  ///   code of it.
  /// </summary>
  TDECHashIncrement8 = class(TDECHash)
  strict protected
    /// <summary>
    ///   Needs to be overridden, even if empty, as it's called internally by
    ///   the class to be tested
    /// </summary>
    procedure DoInit; override;
    /// <summary>
    ///   Needs to be overridden, even if empty, as it's called internally by
    ///   the class to be tested
    /// </summary>
    procedure DoDone; override;
    /// <summary>
    ///   Needs to be overridden, even if empty, as it's called internally by
    ///   the class to be tested
    /// </summary>
    procedure DoTransform(Buffer: PUInt32Array); override;
    /// <summary>
    ///   Needs to be overridden, even if empty, as it's called internally by
    ///   the class to be tested
    /// </summary>
    function Digest: PByteArray; override;
  public
    /// <summary>
    ///   Need to be overriden, as the originals would raise an exception by design
    /// </summary>
    class function DigestSize: UInt32; override;
    /// <summary>
    ///   Need to be overriden, as the originals would raise an exception by design
    /// </summary>
    class function BlockSize: UInt32; override;

    /// <summary>
    ///   Just calls the inherited Increment8 method in order to make it public
    ///   so it can be tested. Internal methods usually do not get unit tested,
    ///   but since this one created quite some heavoc in ASM mode of this library
    ///   (see DECOptions.inc for the necessary define) it deserves some testing.
    /// </summary>
    procedure Increment8(var Value; Add: UInt32);
  end;

  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  THash_TestIncrement8 = class(TTestCase)
  strict protected
    FHashIncr8 : TDECHashIncrement8;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published  // special case: test for Increment8 method due to ASM fixes applied
    procedure TestIncrement8;
  end;

  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  // class for checking some exceptions which get raised for C++ Builder
  THash_TestCPPBuilderExceptions = class(TTestCase)
  strict protected
  public
    procedure SetUp; override;
    procedure TearDown; override;

    procedure DoTestBlockSizeException;
    procedure DoTestDigestSizeException;
  published
    procedure TestBlockSizeException;
    procedure TestDigestSizeException;
  end;

  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  // class for checking all general methods etc. for the password hash base class
  // Testing needs to be done on a concrete derrived class, as that needs to
  // implement the abstract methods as they're used for the basic functionality.
  THash_TestTDECPasswordHash = class(TTestCase)
  private
    FHash : THash_BCrypt;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  protected
    procedure DoTestSaltTooLongException;
    procedure DoTestSaltTooShortException;
    procedure DoTestClassByCryptIdentityException;
  published
    procedure TestGetSalt;
    procedure TestSetSalt;
    procedure TestSaltTooLongException;
    procedure TestSaltTooShortException;
    procedure TestClassByCryptIdentitySuccess;
    procedure TestClassByCryptIdentityException;
  end;

  /// <summary>
  ///   Base class for all hash tests, provides generalized test methods so that
  ///   concrete classes only need to provide the actual test data.
  /// </summary>
  THash_TestBase = class(TTestCase)
  strict protected
    FTestData  : IHashTestDataContainer;
    FHash      : TDECHashAuthentication;

    /// <summary>
    ///   Checks whether a given property exists and if it does sets it to the
    ///   value specified.
    /// </summary>
    /// <param name="aInstance">
    ///   Object instance to check
    /// </param>
    /// <param name="PropertyName">
    ///   Name of the property, not sure if this is case sensitive. The property
    ///   must be public or published to be found
    /// </param>
    /// <param name="Value">
    ///   Value to set the property to. Supported property types currently are:
    ///   Integer, Int64, Float, String and UString.
    /// </param>
    /// <returns>
    ///   true if the property was found and the datatype of it was supported,
    ///   else false
    /// </returns>
    function SetPropertyValue(aInstance: TObject; const PropertyName, Value: string):Boolean;

    // kind of "low-level" test, close to the original test used in DEC5.2
    procedure DoTest52(HashClass:TDECHash); virtual;

    procedure DoTestCalcBuffer(HashClass:TDECHash); virtual;
    procedure DoTestCalcBytes(HashClass:TDECHash); virtual;
    procedure DoTestCalcUnicodeString(HashClass:TDECHash); virtual;
    procedure DoTestCalcRawByteString(HashClass:TDECHash); virtual;

    procedure DoTestClassByName(ExpectedClassName:String; ExpectedClass:TClass);
    procedure DoTestUninitializedException;
  protected
    /// <summary>
    ///   This method has to be overridden in test classes where the hash object
    ///   to be tested needs to have some special properties set. They have to
    ///   be set in this class.
    /// </summary>
    procedure ConfigHashClass(HashClass: TDECHash; IdxTestData:Integer); virtual;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published  // common Tests for all TDECHash classes
    procedure Test52;
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
    procedure TestIsPasswordHash;
    procedure TestGetPaddingByte;
    procedure TestIsPasswordHashBase;
    procedure TestClassByIdentity;
    procedure TestUninitializedException;
  end;

  /// <summary>
  ///   Base class for all non password hash tests, adds the CalcStream/CalcFile
  ///   test methods which are not implemented by the password hash classes.
  ///   Provides generalized test methods so that concrete classes only need to
  ///   provide the actual test data.
  /// </summary>
  THash_TestBaseExtended = class(THash_TestBase)
  strict protected
    procedure DoTestCalcStream(HashClass:TDECHashExtended); virtual;
    // variant for the overload which doesn't return the calculated hash
    procedure DoTestCalcStreamNoDone(HashClass: TDECHashExtended); virtual;
    // variant for the overload which doesn't return the calculated hash and which
    // tries to splitt the input data into multiple calls
    procedure DoTestCalcStreamNoDoneMulti(HashClass: TDECHashExtended); virtual;
    procedure DoTestCalcStreamRawByteString(HashClass: TDECHashExtended); virtual;
  published
    procedure TestCalcStream;
    procedure TestCalcStreamRawByteString;
    procedure TestCalcStreamNoDone;
    procedure TestCalcStreamNoDoneMulti;
  end;

  /// <summary>
  ///   Type for test data specified for Crypt/BSD format tests. Not declared in
  ///   THash_TestPasswordBase as the compiler couldn't find it there.
  /// </summary>
  TCryptTestData = record
                     /// <summary>
                     ///   Number of the password from the password array
                     ///   to use for that test case
                     /// </summary>
                     PWNum: UInt8;
                     /// <summary>
                     ///   Crypt/BSD formatted password storage data
                     /// </summary>
                     CryptData: string;
                   end;

  /// <summary>
  ///   Adds test data initialization common for all password hash algorithms
  /// </summary>
  THash_TestPasswordBase = class(THash_TestBase)
  protected
    procedure ConfigHashClass(aHashClass: TDECHash; aIdxTestData:Integer); override;
  end;

  // Test methods for base class for all hash classes
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECHash = class(TTestCase)
  published
    procedure TestIsClassListCreated;
    procedure TestValidCipherSetDefaultHashClass;
  end;

  // Test methods for class THash_MD2
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_MD2 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_MD4
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_MD4 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_MD5
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_MD5 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_RipeMD128
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_RipeMD128 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_RipeMD160
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_RipeMD160 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_RipeMD256
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_RipeMD256 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_RipeMD320
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_RipeMD320 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_SHA0
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA0 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_SHA, only active if this compatibility define
  // is set
  {$IFDEF OLD_SHA_NAME}
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA = class(TestTHash_SHA0)
  public
    procedure SetUp; override;
  published
    procedure TestClassByName;
    procedure TestIdentity;
  end;
  {$ENDIF}

  // Test methods for class THash_SHA1
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA1 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_SHA256
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA256 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_SHA224
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA224 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_SHA384
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA384 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_SHA512
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_SHA512 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_Haval128
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Haval128 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestGetMaxRounds;
    procedure TestGetMinRounds;
    procedure TestSetRoundsMax;
    procedure TestSetRoundsMin;
  end;

  // Test methods for class THash_Haval160
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Haval160 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestGetMaxRounds;
    procedure TestGetMinRounds;
    procedure TestSetRoundsMax;
    procedure TestSetRoundsMin;
  end;

  // Test methods for class THash_Haval192
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Haval192 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestGetMaxRounds;
    procedure TestGetMinRounds;
    procedure TestSetRoundsMax;
    procedure TestSetRoundsMin;
  end;

  // Test methods for class THash_Haval224
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Haval224 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestGetMaxRounds;
    procedure TestGetMinRounds;
    procedure TestSetRoundsMax;
    procedure TestSetRoundsMin;
  end;

  // Test methods for class THash_Haval256
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Haval256 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestGetMaxRounds;
    procedure TestGetMinRounds;
    procedure TestSetRoundsMax;
    procedure TestSetRoundsMin;
  end;

  // Test methods for class THash_Tiger
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Tiger_3Rounds = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestSetRounds;
    procedure TestSetRoundsLowerLimit;
    procedure TestSetRoundsUpperLimit;
    procedure TestGetMinRounds;
    procedure TestGetMaxRounds;
    procedure TestSetRoundsMin;
    procedure TestSetRoundsMax;

    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_Panama
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Panama = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_Whirlpool0
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Whirlpool0 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName; virtual;
    procedure TestIdentity; virtual;
  end;

  {$IFDEF OLD_WHIRLPOOL_NAMES}
  // Test methods for class THash_Whirlpool
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Whirlpool = class(TestTHash_Whirlpool0)
  public
    procedure SetUp; override;
  published
    procedure TestClassByName; override;
    procedure TestIdentity; override;
  end;
  {$ENDIF}

  // Test methods for class THash_WhirlpoolT
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_WhirlpoolT = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName; virtual;
    procedure TestIdentity; virtual;
  end;

  {$IFDEF OLD_WHIRLPOOL_NAMES}
  // Test methods for class THash_Whirlpool1 aka WhirlpoolT's old name in DEC 5.2
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Whirlpool1 = class(TestTHash_WhirlpoolT)
  public
    procedure SetUp; override;
  published
    procedure TestClassByName; override;
    procedure TestIdentity; override;
  end;
  {$ENDIF}

  {$IFNDEF OLD_WHIRLPOOL_NAMES}
  // Test methods for class THash_Whirlpool1
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Whirlpool1 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName; virtual;
    procedure TestIdentity; virtual;
  end;
  {$ENDIF}

  // Test methods for class THash_Square
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Square = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  // Test methods for class THash_Snefru128
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Snefru128 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestGetMinRounds;
    procedure TestGetMaxRounds;
    procedure TestSetRoundsMin;
    procedure TestSetRoundsMax;
  end;

  // Test methods for class THash_Snefru256
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Snefru256 = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestGetMinRounds;
    procedure TestGetMaxRounds;
    procedure TestSetRoundsMin;
    procedure TestSetRoundsMax;
  end;

  // Test methods for class THash_Sapphire
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_Sapphire = class(THash_TestBaseExtended)
  public
    procedure SetUp; override;
  protected
    procedure ConfigHashClass(aHashClass: TDECHash; aIdxTestData:Integer); override;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
  end;

  /// <summary>
  ///   Test methods for class THash_BCrypt
  /// </summary>
  /// <remarks>
  ///   There is no test with the maximum possible cost value, as even a cost
  ///   value of 20 already takes ages to calculate on a current i5 CPU.
  /// </remarks>
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTHash_BCrypt = class(THash_TestPasswordBase)
  private
    type
      // Extract only the interesting parts
      TBCryptBSDTestData = record
        Salt     : string;
        Cost     : UInt8;
      end;

    const
      Passwords: array[0..4] of string = ('', 'a', 'abc',
                                          'abcdefghijklmnopqrstuvwxyz',
                                          '~!@#$%^&*()      ~!@#$%^&*()PNBFRD');

      // Source of test data: Wolfgang Erhardt's implementation.
      // pn is the index into Passwords
      TestData: array[1..20] of TCryptTestData = (
        (PWNum: 0; CryptData: '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
        (PWNum: 0; CryptData: '$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye'),
        (PWNum: 0; CryptData: '$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW'),
        (PWNum: 0; CryptData: '$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO'),
        (PWNum: 1; CryptData: '$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe'),
        (PWNum: 1; CryptData: '$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V.'),
        (PWNum: 1; CryptData: '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
        (PWNum: 1; CryptData: '$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS'),
        (PWNum: 2; CryptData: '$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'),
        (PWNum: 2; CryptData: '$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm'),
        (PWNum: 2; CryptData: '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
        (PWNum: 2; CryptData: '$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q'),
        (PWNum: 3; CryptData: '$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC'),
        (PWNum: 3; CryptData: '$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz.'),
        (PWNum: 3; CryptData: '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
        (PWNum: 3; CryptData: '$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG'),
        (PWNum: 4; CryptData: '$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO'),
        (PWNum: 4; CryptData: '$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW'),
        (PWNum: 4; CryptData: '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
        (PWNum: 4; CryptData: '$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC'));

    function SplitTestVector(const Vector: string):TBCryptBSDTestData;
  protected
    procedure ConfigHashClass(aHashClass: TDECHash; aIdxTestData:Integer); override;
  public
    procedure SetUp; override;
    procedure DoTestCostFactorTooShortException;
    procedure DoTestCostFactorTooLongException;
    procedure DoTestNoSaltSpecified;
    procedure DoTestTooShortSaltSpecified;
    procedure DoTestTooLongSaltSpecified;
    procedure DoTestTooLongPasswordSpecified;
  published
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
    procedure TestClassByName;
    procedure TestIdentity;
    procedure TestMaximumSaltLength;
    procedure TestMinimumSaltLength;
    procedure TestMaximumPasswordLength;
    procedure TestMinCost;
    procedure TestMaxCost;
    procedure TestCostFactorTooShortException;
    procedure TestCostFactorTooLongException;
    procedure TestSetGetCostFactor;
    procedure TestCreateCryptBSDFormatString;
    procedure TestCreateCryptBSDFormatTBytes;
    procedure TestIsValidPasswordOKString;
    procedure TestIsValidPasswordOKTBytes;
    procedure TestIsValidPasswordFalseString;
    procedure TestIsValidPasswordFalseTBytes;
    procedure TestNoSaltSpecified;
    procedure TestTooShortSaltSpecified;
    procedure TestTooLongSaltSpecified;
    procedure TestTooLongPasswordException;
  end;

implementation

uses
  System.TypInfo, System.Rtti,
  DECHashInterface, DECFormat;

procedure TestTHash_MD2.SetUp;
var
  lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_MD2.Create;

  // Source: all including 12345678901234567890123456789012345678901234567890123
  // 456789012345678901234567890 are from: https://www.ietf.org/rfc/rfc1319.txt
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8350e5a3e24c153df2275c9f80692773';
  lDataRow.ExpectedOutputUTFStrTest := '8350e5a3e24c153df2275c9f80692773';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '32ec01ec4a6dac72c0ab96fb34c0b5d1';
  lDataRow.ExpectedOutputUTFStrTest := 'a732378b5c5e0cb55543fbbcc9618d58';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'da853b0d3f88d99b30283a69e6ded6bb';
  lDataRow.ExpectedOutputUTFStrTest := '64bc320671ffdb9b433c36693b942852';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ab4f496bfb2a530b219ff33031fe06b0';
  lDataRow.ExpectedOutputUTFStrTest := 'ed4c934d78222a95c1a4de10bac74258';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4e8ddff3650292ab5a4108c3aa47940b';
  lDataRow.ExpectedOutputUTFStrTest := 'f6456db6a2e5608a2c36cd9c0dc5169d';
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'da33def2a42df13975352846c30338cd';
  lDataRow.ExpectedOutputUTFStrTest := 'c4c41d053cba1f7924ca33029724eddf';
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd5976f79d83d3a0dc9806c3c66f3efd8';
  lDataRow.ExpectedOutputUTFStrTest := 'a6dcaf889aaa5738141b713d8e4fc6c3';
  lDataRow.AddInputVector('12345678901234567890123456789012345678901234567890123' +
                          '456789012345678901234567890');

  // Source: German MD2 Wikipedia article as of 30.05.2021
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8415570a6653a06314f09b023612a92d';
  lDataRow.ExpectedOutputUTFStrTest := '9d76631406e8be4ed7284613edf23fd5';
  lDataRow.AddInputVector('Franz jagt im komplett verwahrlosten Taxi quer durch Bayern');

  // Source: German MD2 Wikipedia article as of 30.05.2021
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b0e27e91b84246bc4c38bc3008f00374';
  lDataRow.ExpectedOutputUTFStrTest := 'b2ea09572c2fcfb278afd72155bc28e7';
  lDataRow.AddInputVector('Frank jagt im komplett verwahrlosten Taxi quer durch Bayern');
end;

procedure TestTHash_MD2.TestDigestSize;
begin
  CheckEquals(16, FHash.DigestSize);
end;

procedure TestTHash_MD2.TestIdentity;
begin
  CheckEquals($D3A02D0F, FHash.Identity);
end;

procedure TestTHash_MD2.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_MD2.TestBlockSize;
begin
  CheckEquals(16, FHash.BlockSize);
end;

procedure TestTHash_MD2.TestClassByName;
begin
  DoTestClassByName('THash_MD2', THash_MD2);
end;

procedure TestTHash_MD4.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_MD4.Create;

  // Source for all until SourceEnd: https://datatracker.ietf.org/doc/html/rfc1320
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '31d6cfe0d16ae931b73c59d7e0c089c0';
  lDataRow.ExpectedOutputUTFStrTest := '31d6cfe0d16ae931b73c59d7e0c089c0';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bde52cb31de33e46245e05fbdbd6fb24';
  lDataRow.ExpectedOutputUTFStrTest := '186cb09181e2c2ecaac768c47c729904';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a448017aaf21d8525fc10ae87aa6729d';
  lDataRow.ExpectedOutputUTFStrTest := 'e0fba38268d0ec66ef1cb452d5885e53';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd9130a8164549fe818874806e1c7014b';
  lDataRow.ExpectedOutputUTFStrTest := '94a8a6cc36108b93db330de54b90bd4b';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd79e1c308aa5bbcdeea8ed63df412da9';
  lDataRow.ExpectedOutputUTFStrTest := '0bd63185f3484bb000286c85917dc12e';
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '043f8582f241db351ce627e153e7f0e4';
  lDataRow.ExpectedOutputUTFStrTest := '2e74cc46c96ee4caee5df20d0898fef8';
  lDataRow.AddInputVector('A');
  lDataRow.AddInputVector('BCDEFGHIJKLMNOPQRS');
  lDataRow.AddInputVector('TUVWXYZabcdefghijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e33b4ddc9c38f2199c3e7b164fcc0536';
  lDataRow.ExpectedOutputUTFStrTest := 'cf17b1ae2606afa964193690df7543b1';
  lDataRow.AddInputVector('1234567890', 1, 8);
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '186767a4d851893b823e6824c6efda62';
  lDataRow.ExpectedOutputUTFStrTest := '720710bdf5588ff54a1541168c49ffbc';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized '+
                          'block necessity decision error. This block has total '+
                          'length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'adba72c3baf834d091eb59f18d022549';
  lDataRow.ExpectedOutputUTFStrTest := '077ff2742a36a53d86774f01e4911f46';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized '+
                          'block necessity decision error. This block has total '+
                          'length 120 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bbce80cc6bb65e5c6745e30d4eeca9a4';
  lDataRow.ExpectedOutputUTFStrTest := '29830de36ff8d3c23c73535ed6d1c69f';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bbce80cc6bb65e5c6745e30d4eeca9a4';
  lDataRow.ExpectedOutputUTFStrTest := '29830de36ff8d3c23c73535ed6d1c69f';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
end;

procedure TestTHash_MD4.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_MD4.TestDigestSize;
begin
  CheckEquals(16, FHash.DigestSize);
end;

procedure TestTHash_MD4.TestIdentity;
begin
  CheckEquals($3AC3883A, FHash.Identity);
end;

procedure TestTHash_MD4.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_MD4.TestClassByName;
begin
  DoTestClassByName('THash_MD4', THash_MD4);
end;

procedure TestTHash_MD5.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_MD5.Create;

  // Source for all until SourceEnd: https://datatracker.ietf.org/doc/html/rfc1321
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd41d8cd98f00b204e9800998ecf8427e';
  lDataRow.ExpectedOutputUTFStrTest := 'd41d8cd98f00b204e9800998ecf8427e';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0cc175b9c0f1b6a831c399e269772661';
  lDataRow.ExpectedOutputUTFStrTest := '4144e195f46de78a3623da7364d04f11';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '900150983cd24fb0d6963f7d28e17f72';
  lDataRow.ExpectedOutputUTFStrTest := 'ce1473cf80c6b3fda8e3dfc006adc315';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f96b697d7cb7938d525a2f31aaf161d0';
  lDataRow.ExpectedOutputUTFStrTest := '6f9ab83227f65f9b86c380e2c9c33031';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c3fcd3d76192e4007dfb496cca67e13b';
  lDataRow.ExpectedOutputUTFStrTest := '35020d67a52d8e915330f0a77f676bbf';
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd174ab98d277d9f5a5611c2c9f419d9f';
  lDataRow.ExpectedOutputUTFStrTest := '86056d805455c8448f6c09404c3db624';
  lDataRow.AddInputVector('A');
  lDataRow.AddInputVector('BCDEFGHIJKLMNOPQRS');
  lDataRow.AddInputVector('TUVWXYZabcdefghijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '57edf4a22be3c955ac49da2e2107b67a';
  lDataRow.ExpectedOutputUTFStrTest := '903f43f5c1f384fc267110bf07caec04';
  lDataRow.AddInputVector('1234567890', 8);
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e6810238956987dec0d7bfcbcd4caab8';
  lDataRow.ExpectedOutputUTFStrTest := 'a36d511965e2c68794b5fbfe54d74b8c';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized '+
                          'block necessity decision error. This block has total '+
                          'length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '637d2777ed733d5d33b5bfc140f118c5';
  lDataRow.ExpectedOutputUTFStrTest := '3995d2a93d5df46406ef04b34d06b177';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized '+
                          'block necessity decision error. This block has total '+
                          'length 120 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7707d6ae4e027c70eea2a935c2296f21';
  lDataRow.ExpectedOutputUTFStrTest := '168f7302c596180bb5372f5015098742';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7707d6ae4e027c70eea2a935c2296f21';
  lDataRow.ExpectedOutputUTFStrTest := '168f7302c596180bb5372f5015098742';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
end;

procedure TestTHash_MD5.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_MD5.TestDigestSize;
begin
  CheckEquals(16, FHash.DigestSize);
end;

procedure TestTHash_MD5.TestIdentity;
begin
  CheckEquals($4DC4B8AC, FHash.Identity);
end;

procedure TestTHash_MD5.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_MD5.TestClassByName;
begin
  DoTestClassByName('THash_MD5', THash_MD5);
end;

procedure TestTHash_RipeMD128.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  // Source until SourceEnd: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
  FHash := THash_RipeMD128.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cdf26213a150dc3ecb610f18f6b38b46';
  lDataRow.ExpectedOutputUTFStrTest := 'cdf26213a150dc3ecb610f18f6b38b46';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '86be7afa339d0fc7cfc785e72f578d33';
  lDataRow.ExpectedOutputUTFStrTest := 'b7d45de39098253a3c98c2756101f5aa';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c14a12199c66e4ba84636b0f69144c77';
  lDataRow.ExpectedOutputUTFStrTest := '464176f18edc59cb59f7b08e2a6e404f';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9e327b3d6e523062afc1132d7df9d1b8';
  lDataRow.ExpectedOutputUTFStrTest := '8adb8445ef4925f7483e0b1738f3e6b3';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'fd2aa607f71dc8f510714922b371834e';
  lDataRow.ExpectedOutputUTFStrTest := '7b841da3c9bd2923afe8b8c91f7036ae';
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a1aa0689d0fafa2ddc22e88b49133a06';
  lDataRow.ExpectedOutputUTFStrTest := 'f2d7d9201198f9b54392033127e59e11';
  lDataRow.AddInputVector('abcdbcdecdefdefg');
  lDataRow.AddInputVector('efghfghighijhijki');
  lDataRow.AddInputVector('jkljklmklmnlmnomnopnopq');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd1e959eb179c911faea4624c60c5c702';
  lDataRow.ExpectedOutputUTFStrTest := 'b9c16efbf21603ccc20895609999ab75';
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3f45ef194732c2dbb2c4a2c769795fa3';
  lDataRow.ExpectedOutputUTFStrTest := '48c714a46e60f21802adef5c60b5b63e';
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a4137d8c40fa51152905b3747acc0ff4';
  lDataRow.ExpectedOutputUTFStrTest := 'd08312b9507ea0edbc38c4b1d421e0f1';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '243988f60681af64730a7ee6b5f0406b';
  lDataRow.ExpectedOutputUTFStrTest := 'c227947947ad2085bd35817cf94be3d3';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4a7f5723f954eba1216c9d8f6320431f';
  lDataRow.ExpectedOutputUTFStrTest := 'c8c6d2c7e48fc3788ef778426d4382e0';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4a7f5723f954eba1216c9d8f6320431f';
  lDataRow.ExpectedOutputUTFStrTest := 'c8c6d2c7e48fc3788ef778426d4382e0';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
  // SourceEnd
end;

procedure TestTHash_RipeMD128.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_RipeMD128.TestDigestSize;
begin
  CheckEquals(16, FHash.DigestSize);
end;

procedure TestTHash_RipeMD128.TestIdentity;
begin
  CheckEquals($47EEAE41, FHash.Identity);
end;

procedure TestTHash_RipeMD128.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_RipeMD128.TestClassByName;
begin
  DoTestClassByName('THash_RipeMD128', THash_RipeMD128);
end;

procedure TestTHash_RipeMD160.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_RipeMD160.Create;

  // Source until SourceEnd: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9c1185a5c5e9fc54612808977ee8f548b2258d31';
  lDataRow.ExpectedOutputUTFStrTest := '9c1185a5c5e9fc54612808977ee8f548b2258d31';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe';
  lDataRow.ExpectedOutputUTFStrTest := '3213d398bb951aa09625539093524fa528848bd0';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc';
  lDataRow.ExpectedOutputUTFStrTest := '44bfc4965cb140dc9bea1f842a9deabdae0be453';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5d0689ef49d2fae572b881b123a85ffa21595f36';
  lDataRow.ExpectedOutputUTFStrTest := '3648d57f2b151f9bd2ef3f3d8d16efa869bb7552';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc';
  lDataRow.ExpectedOutputUTFStrTest := '2471799ad0ee46968fa5bd32beac4e86da2e956d';
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '12a053384a9c0c88e405a06c27dcf49ada62eb2b';
  lDataRow.ExpectedOutputUTFStrTest := '11d9f9253bf89efc0de965398321c3a40350abc1';
  lDataRow.AddInputVector('abcdbcdecdefdefg');
  lDataRow.AddInputVector('efghfghighijhijki');
  lDataRow.AddInputVector('jkljklmklmnlmnomnopnopq');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b0e20b6e3116640286ed3a87a5713079b21f5189';
  lDataRow.ExpectedOutputUTFStrTest := 'cc2712643bb383eadc72099d85d50bc879c93b74';
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9b752e45573d4b39f4dbd3323cab82bf63326bfb';
  lDataRow.ExpectedOutputUTFStrTest := '5b9333be43b8900e33224375f3a22b66a4d77388';
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b8c681512ad02967243bb93d181b5783eb501f2f';
  lDataRow.ExpectedOutputUTFStrTest := '99079db8b7532db2699a69ca200dab8eeb8be77e';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e94a9d107e49e4ea81b22cfaa4075437175d383c';
  lDataRow.ExpectedOutputUTFStrTest := 'a9a5a0eb2c69ddb61774054cbf800256f7eb4ac9';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '52783243c1697bdbe16d37f97f68f08325dc1528';
  lDataRow.ExpectedOutputUTFStrTest := '98182142d06b9952b1c7568fd0d178100e61c098';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '52783243c1697bdbe16d37f97f68f08325dc1528';
  lDataRow.ExpectedOutputUTFStrTest := '98182142d06b9952b1c7568fd0d178100e61c098';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
  // SourceEnd
end;

procedure TestTHash_RipeMD160.TestDigestSize;
begin
  CheckEquals(20, FHash.DigestSize);
end;

procedure TestTHash_RipeMD160.TestIdentity;
begin
  CheckEquals($2D59E377, FHash.Identity);
end;

procedure TestTHash_RipeMD160.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_RipeMD160.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_RipeMD160.TestClassByName;
begin
  DoTestClassByName('THash_RipeMD160', THash_RipeMD160);
end;

procedure TestTHash_RipeMD256.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_RipeMD256.Create;

  // Source until SourceEnd: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html#extensions
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d';
  lDataRow.ExpectedOutputUTFStrTest := '02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925';
  lDataRow.ExpectedOutputUTFStrTest := '9085ecd33f28d345d80830edb9bc9dbdf864810e51538db16b14f229fcce02c2';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65';
  lDataRow.ExpectedOutputUTFStrTest := 'e65742e3316aafdaf74854b5e7406ac7de565d5a8352eb305e00249e158c5bf1';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e';
  lDataRow.ExpectedOutputUTFStrTest := '8456b94a8564fca0356765e9e3e0ccda4af6cd486e65ce1259559143c44ba0ea';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133';
  lDataRow.ExpectedOutputUTFStrTest := 'd2ed143760b33fc5c338a39d5bbe4296f7a95a60bbb09d479c2708915bd4c281';
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f';
  lDataRow.ExpectedOutputUTFStrTest := '9b33e9ed9a3de3a7f018f76e7c3606d67d5da7fe928b4034a9ea05cf3714db3f';
  lDataRow.AddInputVector('abcdbcdecdefdefg');
  lDataRow.AddInputVector('efghfghighijhijki');
  lDataRow.AddInputVector('jkljklmklmnlmnomnopnopq');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8';
  lDataRow.ExpectedOutputUTFStrTest := '9b977a9dc14a8398b42a38f156e6f15063d26e26e4bc900ba544f2708990fdd8';
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd';
  lDataRow.ExpectedOutputUTFStrTest := '67e959944ad20f439af5cffa4893b5913536bba2e151b7c5bd01da6707fd331c';
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ce2a12e4361b03bf914ce35267628a9f26d54ed82b764c903958f29e652e0f5d';
  lDataRow.ExpectedOutputUTFStrTest := 'fc0f03e8f9666aa901ddb32482eef939b1abc86d311439ed022b4ece5194363c';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5b622dfcf325aa4476bcdeff971f961120a19bf7642b85cbdd422f46d7c7bad8';
  lDataRow.ExpectedOutputUTFStrTest := '3015a97978ad2824ab545aabc411f78b4b6e44acb23a865af696ef5777f7703a';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978';
  lDataRow.ExpectedOutputUTFStrTest := 'bcda054f27f32fedeb8374ee93d01fbc0783c30b9e71cc3e2a463265eac08f76';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978';
  lDataRow.ExpectedOutputUTFStrTest := 'bcda054f27f32fedeb8374ee93d01fbc0783c30b9e71cc3e2a463265eac08f76';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
  // SourceEnd
end;

procedure TestTHash_RipeMD256.TestDigestSize;
begin
  CheckEquals(32, FHash.DigestSize);
end;

procedure TestTHash_RipeMD256.TestIdentity;
begin
  CheckEquals($ED51ABD8, FHash.Identity);
end;

procedure TestTHash_RipeMD256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_RipeMD256.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_RipeMD256.TestClassByName;
begin
  DoTestClassByName('THash_RipeMD256', THash_RipeMD256);
end;

procedure TestTHash_RipeMD320.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_RipeMD320.Create;

  // Source until SourceEnd: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html#extensions
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8';
  lDataRow.ExpectedOutputUTFStrTest := '22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d';
  lDataRow.ExpectedOutputUTFStrTest := 'becac9657471217026a3e463c4e4198d0a35a628d5b33ea9ce3bfe2e1ec03c8e48d4c71bac843224';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d';
  lDataRow.ExpectedOutputUTFStrTest := '4c00c48edf4a07ef988899ee8a2284122c411c975db403e680b90ba7b9d314791a18a12a5f2931b8';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197';
  lDataRow.ExpectedOutputUTFStrTest := 'f18db73fd25af066beeb55389f10f21b0598075bc2febd0fb30f30293e4f08e8d4af496d38103f83';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009';
  lDataRow.ExpectedOutputUTFStrTest := '772143ae4d541d7762a53b0844630b1ecdbc52ffb119c9ab3b6eab1d208c0fae32083893af448a4d';
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac';
  lDataRow.ExpectedOutputUTFStrTest := 'de99fd0c2a981d986935e66be800d6b408e0b4190a0710ea05fc48417a906216e5783344bf34104b';
  lDataRow.AddInputVector('abcdbcdecdefdefg');
  lDataRow.AddInputVector('efghfghighijhijki');
  lDataRow.AddInputVector('jkljklmklmnlmnomnopnopq');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4';
  lDataRow.ExpectedOutputUTFStrTest := '0a85ae029693b50fd975ea1444785634b33df413f3698741300ae30b7aace18e70e03e456d10e51e';
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42';
  lDataRow.ExpectedOutputUTFStrTest := '2de7b865e6692c84c0f23116e609fc99b5717a2c38028e45cdb00cbd5df70fcac63f23aa6493a3a3';
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '83254b7c45b10b0f1c7cd9d6bdf1c318d4e807731b7ce21b348ac0ee17e4ee7feb1f49fc3aea7d16';
  lDataRow.ExpectedOutputUTFStrTest := '32c9e60055988f4d00284a9a1e6c0d27eb10fc5429dfb2a168fc6016b32759c442586c566f30d941';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '77d7e20be0672bc74ed1cb4d9f56cf455c5e86a045c18db84e2d7bba53b21788575d6d7baa3d3469';
  lDataRow.ExpectedOutputUTFStrTest := 'df1d29aec8620e470c45cf77852c7b917877c80d2f63a279b41cc0d65fc5c93c5bd35c08cf08db91';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66';
  lDataRow.ExpectedOutputUTFStrTest := '532260a4e62a359a9d1561a1e6cfd1f6988447a3ef4f810a252f69483e4ad5d7f95fc1609d29bb1a';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66';
  lDataRow.ExpectedOutputUTFStrTest := '532260a4e62a359a9d1561a1e6cfd1f6988447a3ef4f810a252f69483e4ad5d7f95fc1609d29bb1a';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
  // SourceEnd
end;


procedure TestTHash_RipeMD320.TestDigestSize;
begin
  CheckEquals(40, FHash.DigestSize);
end;

procedure TestTHash_RipeMD320.TestIdentity;
begin
  CheckEquals($4AB1F21D, FHash.Identity);
end;

procedure TestTHash_RipeMD320.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_RipeMD320.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_RipeMD320.TestClassByName;
begin
  DoTestClassByName('THash_RipeMD320', THash_RipeMD320);
end;

procedure TestTHash_SHA0.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_SHA0.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f96cea198ad1dd5617ac084a3d92c6107708c0ef';
  lDataRow.ExpectedOutputUTFStrTest := 'f96cea198ad1dd5617ac084a3d92c6107708c0ef';
  lDataRow.AddInputVector('');

  // Source until SourceEnd: NIST.FIPS.180.pdf
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0164b8a914cd2a5e74c4f7ff082c4d97f1edf880';
  lDataRow.ExpectedOutputUTFStrTest := 'e286e14cff397cd7e37f755e00af6a8e1b00bc55';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd2516ee1acfa5baf33dfc1c471e438449ef134c8';
  lDataRow.ExpectedOutputUTFStrTest := '97163d17d936aa26b97bfad5d8ae1e328e29c532';
  lDataRow.AddInputVector('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3232affa48628a26653b5aaa44541fd90d690603';
  lDataRow.ExpectedOutputUTFStrTest := '209d48020a6dff914d1503e2a760d4ef4ad4c8fe';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3232affa48628a26653b5aaa44541fd90d690603';
  lDataRow.ExpectedOutputUTFStrTest := '209d48020a6dff914d1503e2a760d4ef4ad4c8fe';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f79e92290e9f519a62467812ea56920850354796';
  lDataRow.ExpectedOutputUTFStrTest := '53f1df401054ccfa66250ace1454b34d55059e3c';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e644dc674505c8260e58e32f6b8bcf565b2fafc4';
  lDataRow.ExpectedOutputUTFStrTest := '29a30604bfbd1c23545fd02faf4c6bbce9947377';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.');
end;

procedure TestTHash_SHA0.TestDigestSize;
begin
  CheckEquals(20, FHash.DigestSize);
end;

procedure TestTHash_SHA0.TestIdentity;
begin
  CheckEquals($0C266BE5, FHash.Identity);
end;

procedure TestTHash_SHA0.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_SHA0.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_SHA0.TestClassByName;
begin
  DoTestClassByName('THash_SHA0', THash_SHA0);
end;

{$IFDEF OLD_SHA_NAME}
procedure TestTHash_SHA.SetUp;
begin
  inherited;

  FHash.free;
  FHash := THash_SHA.Create;
end;

procedure TestTHash_SHA.TestIdentity;
begin
  CheckEquals($A0A1CCFF, FHash.Identity);
end;

procedure TestTHash_SHA.TestClassByName;
begin
  DoTestClassByName('THash_SHA', THash_SHA);
end;
{$ENDIF}

{ TestTHash_SHA1 }

procedure TestTHash_SHA1.SetUp;
var
  lDataRow : IHashTestDataRowSetup;
  i        : Integer;
  rs       : RawByteString;
begin
  inherited;

  FHash := THash_SHA1.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
  lDataRow.ExpectedOutputUTFStrTest := 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
  lDataRow.AddInputVector('');

  // Source until SourceEnd: German Wikipedia
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '68ac906495480a3404beee4874ed853a037a7a8f';
  lDataRow.ExpectedOutputUTFStrTest := 'ca2bea5813b6914b6d75ee6975af2aa99b7f09ca';
  lDataRow.AddInputVector('Franz jagt im komplett verwahrlosten Taxi quer durch Bayern');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '89fdde0b28373dc4f361cfb810b35342cc2c3232';
  lDataRow.ExpectedOutputUTFStrTest := '41e9761e0427676d8b5aead6631c5e7bc2946e81';
  lDataRow.AddInputVector('Granz jagt im komplett verwahrlosten Taxi quer durch Bayern');
  // SourceEnd

  // Source until SourceEnd: https://datatracker.ietf.org/doc/html/rfc4634
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a9993e364706816aba3e25717850c26c9cd0d89d';
  lDataRow.ExpectedOutputUTFStrTest := '9f04f41a848514162050e3d68c1a7abb441dc2b5';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '84983e441c3bd26ebaae4aa1f95129e5e54670f1';
  lDataRow.ExpectedOutputUTFStrTest := '51d7d8769ac72c409c5b0e3f69c60adc9a039014';
  lDataRow.AddInputVector('abcdbcdecdefdef');
  lDataRow.AddInputVector('gefghfghighijhijki');
  lDataRow.AddInputVector('jkljklmklmnlmnomnopnop');
  lDataRow.AddInputVector('q');

  rs := '';
  for i := 1 to 15625 do
    rs := rs + 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '34aa973cd4c4daa4f61eeb2bdbad27316534016f';
  lDataRow.ExpectedOutputUTFStrTest := 'c4609560a108a0c626aa7f2b38a65566739353c5';
  lDataRow.AddInputVector(rs);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'dea356a2cddd90c7a7ecedc5ebb563934f460452';
  lDataRow.ExpectedOutputUTFStrTest := '0600f3d950b5a289a1d9da127f6ad0b946f533d8';
  lDataRow.AddInputVector('01234567012345670123456701234567', 10, 2);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '82abff6605dbe1c17def12a394fa22a82b544a35';
  lDataRow.ExpectedOutputUTFStrTest := '0835aef8def1f766c534cc36694f6af813312529';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\x9a\x7d\xfd\xf1\xec\xea\xd0\x6e\xd6\x46\xaa\x55\xfe\x75\x71\x46'));

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cb0082c8f197d260991ba6a460e76e202bad27b3';
  lDataRow.ExpectedOutputUTFStrTest := '5c64c33b3df55af4120314c10614a102e0feada9';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\xf7\x8f\x92\x14\x1b\xcd\x17\x0a\xe8\x9b\x4f\xba\x15\xa1\xd5\x9f' +
                                                '\x3f\xd8\x4d\x22\x3c\x92\x51\xbd\xac\xbb\xae\x61\xd0\x5e\xd1\x15' +
                                                '\xa0\x6a\x7c\xe1\x17\xb7\xbe\xea\xd2\x44\x21\xde\xd9\xc3\x25\x92' +
                                                '\xbd\x57\xed\xea\xe3\x9c\x39\xfa\x1f\xe8\x94\x6a\x84\xd0\xcf\x1f' +
                                                '\x7b\xee\xad\x17\x13\xe2\xe0\x95\x98\x97\x34\x7f\x67\xc8\x0b\x04' +
                                                '\x00\xc2\x09\x81\x5d\x6b\x10\xa6\x83\x83\x6f\xd5\x56\x2a\x56\xca' +
                                                '\xb1\xa2\x8e\x81\xb6\x57\x66\x54\x63\x1c\xf1\x65\x66\xb8\x6e\x3b' +
                                                '\x33\xa1\x08\xb0\x53\x07\xc0\x0a\xff\x14\xa7\x68\xed\x73\x50\x60' +
                                                '\x6a\x0f\x85\xe6\xa9\x1d\x39\x6f\x5b\x5c\xbe\x57\x7f\x9b\x38\x80' +
                                                '\x7c\x7d\x52\x3d\x6d\x79\x2f\x6e\xbc\x24\xa4\xec\xf2\xb3\xa4\x27' +
                                                '\xcd\xbb\xfb'));
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c464f3b38d34f7bf49b29635e50c8957b3a87dc7';
  lDataRow.ExpectedOutputUTFStrTest := '65bbefb5a727dedc039540dc1dcfa18c6fa3aeec';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'df2724a78d507fbfb4b85aa328cf8221e10f74a7';
  lDataRow.ExpectedOutputUTFStrTest := '634f2fd10ec73d75bd976990064edfc1e9d75cd5';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.');
end;

procedure TestTHash_SHA1.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_SHA1.TestClassByName;
begin
  DoTestClassByName('THash_SHA1', THash_SHA1);
end;

procedure TestTHash_SHA1.TestDigestSize;
begin
  CheckEquals(20, FHash.DigestSize);
end;

procedure TestTHash_SHA1.TestIdentity;
begin
  CheckEquals($7B215B73, FHash.Identity);
end;

procedure TestTHash_SHA1.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_SHA256.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_SHA256.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  lDataRow.ExpectedOutputUTFStrTest := 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  lDataRow.AddInputVector('');

  // Source until SourceEnd: https://datatracker.ietf.org/doc/html/rfc4634
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  lDataRow.ExpectedOutputUTFStrTest := '13e228567e8249fce53337f25d7970de3bd68ab2653424c7b8f9fd05e33caedf';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1';
  lDataRow.ExpectedOutputUTFStrTest := 'fa84fa96dd6f1a0fda1769cacec9bac12efadad72ab60ff68ec5ae1a4d3fab8e';
  lDataRow.AddInputVector('abcdbcdecdefdef');
  lDataRow.AddInputVector('gefghfghighijhijki');
  lDataRow.AddInputVector('jkljklmklmnlmnomnopnop');
  lDataRow.AddInputVector('q');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0';
  lDataRow.ExpectedOutputUTFStrTest := 'a0bc50078623514a87e96de81d8d200527a1b1150acd92252d88aa109dfa0aa4';
  lDataRow.AddInputVector('a', 1, 1000000);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5';
  lDataRow.ExpectedOutputUTFStrTest := '9c27762fb6a10478e2e306ddc4db3ec18529c00227dbd2c0555a31d047d8da12';
  lDataRow.AddInputVector('01234567012345670123456701234567', 1, 20);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '175ee69b02ba9b58e2b0a5fd13819cea573f3940a94f825128cf4209beabb4e8';
  lDataRow.ExpectedOutputUTFStrTest := '77d0d74c83fc00e4dcac550a425417d67ccad6487dfdc9f15bb14153f39d781e';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52'));

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '97dbca7df46d62c8a422c941dd7e835b8ad3361763f7e9b2d95f4f0da6e1ccbc';
  lDataRow.ExpectedOutputUTFStrTest := '14f3a8f8b751040ed71029032db016e4f17be48709cffd71695ac58020fa7235';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\x83\x26\x75\x4e\x22\x77\x37\x2f' +
                                                '\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0' +
                                                '\x4d\x8a\x05\x69\x71\xb1\x1a\xd5' +
                                                '\x71\x23\xa7\xc1\x37\x76\x00\x00' +
                                                '\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08' +
                                                '\x3a\xa3\x9d\x81\x0d\xb3\x10\x77' +
                                                '\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a' +
                                                '\x26\xc7\x73\x32\x5f\x8b\x23\x74' +
                                                '\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c' +
                                                '\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b' +
                                                '\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f' +
                                                '\x9d\x65\x92\xec\xed\xaa\x66\xca' +
                                                '\x82\xa2\x9d\x0c\x51\xbc\xf9\x33' +
                                                '\x62\x30\xe5\xd7\x84\xe4\xc0\xa4' +
                                                '\x3f\x8d\x79\xa3\x0a\x16\x5c\xba' +
                                                '\xbe\x45\x2b\x77\x4b\x9c\x71\x09' +
                                                '\xa9\x7d\x13\x8f\x12\x92\x28\x96' +
                                                '\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a' +
                                                '\x9f\xdd\x30\x82\x57\x69\xb2\xc6' +
                                                '\x71\xaf\x67\x59\xdf\x28\xeb\x39' +
                                                '\x3d\x54\xd6'));
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '85c0f2421bdffd1dc9568cd815175fe286e5c18a4c4e0308114f534442c6dc3c';
  lDataRow.ExpectedOutputUTFStrTest := 'c4ccadb4452fd1e52ca9e90e4447a2f093b4bf2acd5a1e2293ef622e0a166b53';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c8a0bcda5fec642e44488fd7b782821d478ef17e651eaec0e43f9036388340bb';
  lDataRow.ExpectedOutputUTFStrTest := '2f8aa82881b1140af41e95bf96ded6d034654492007b7302e1bd9231ce99bdf3';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.');
end;

procedure TestTHash_SHA256.TestDigestSize;
begin
  CheckEquals(32, FHash.DigestSize);
end;

procedure TestTHash_SHA256.TestIdentity;
begin
  CheckEquals($9EE7F031, FHash.Identity);
end;

procedure TestTHash_SHA256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_SHA256.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_SHA256.TestClassByName;
begin
  DoTestClassByName('THash_SHA256', THash_SHA256);
end;

{ TestTHash_SHA224 }

procedure TestTHash_SHA224.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;
  FHash := THash_SHA224.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f';
  lDataRow.ExpectedOutputUTFStrTest := 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f';
  lDataRow.AddInputVector('');

  // Source until SourceEnd: https://datatracker.ietf.org/doc/html/rfc4634
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7';
  lDataRow.ExpectedOutputUTFStrTest := '57ba76af9d4846f1e08697d79422ea3f516fe3145ad7fc4c93ba85ac';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525';
  lDataRow.ExpectedOutputUTFStrTest := '2d30dab9655cd28a84790ae02e742d28b02c1d5d2e7196cee1732ca5';
  lDataRow.AddInputVector('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67';
  lDataRow.ExpectedOutputUTFStrTest := '11bb18d73d725c7d104e1ca15ee9b5094c3703ac152ffb2484b45a78';
  lDataRow.AddInputVector('a', 1, 1000000);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '567f69f168cd7844e65259ce658fe7aadfa25216e68eca0eb7ab8262';
  lDataRow.ExpectedOutputUTFStrTest := 'e0a85c282eafe3eb64012b257df2e692fdb4ff9e157ad145b5d753ad';
  lDataRow.AddInputVector('01234567012345670123456701234567', 1, 20);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'df90d78aa78821c99b40ba4c966921accd8ffb1e98ac388e56191db1';
  lDataRow.ExpectedOutputUTFStrTest := '12afe1e6d3b55e3934a3017aba520a9b1be4b585c5965bbc946ace53';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\x18\x80\x40\x05\xdd\x4f\xbd\x15\x56\x29\x9d' +
                                                '\x6f\x9d\x93\xdf\x62'));
  // SourceEnd

  // Source until SOurceEnd: German Wikipedia
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '49b08defa65e644cbf8a2dd9270bdededabc741997d1dadd42026d7b';
  lDataRow.ExpectedOutputUTFStrTest := '17736c9fe07a99442d402a22f6a4a46014e0ea8196508d330e716674';
  lDataRow.AddInputVector('Franz jagt im komplett verwahrlosten Taxi quer durch Bayern');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '58911e7fccf2971a7d07f93162d8bd13568e71aa8fc86fc1fe9043d1';
  lDataRow.ExpectedOutputUTFStrTest := 'a90f803e04789e2e0984730b4d9c1c71a0921bd714f1a874e13fef29';
  lDataRow.AddInputVector('Frank jagt im komplett verwahrlosten Taxi quer durch Bayern');
  // SourceEnd
end;

procedure TestTHash_SHA224.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_SHA224.TestClassByName;
begin
  DoTestClassByName('THash_SHA224', THash_SHA224);
end;

procedure TestTHash_SHA224.TestDigestSize;
begin
  CheckEquals(28, FHash.DigestSize);
end;

procedure TestTHash_SHA224.TestIdentity;
begin
  CheckEquals($3FA807DA, FHash.Identity);
end;

procedure TestTHash_SHA224.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_SHA384.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_SHA384.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0' +
                                       'cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b';
  lDataRow.ExpectedOutputUTFStrTest := '38b060a751ac96384cd9327eb1b1e36a21fdb71114be0' +
                                       '7434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b';
  lDataRow.AddInputVector('');

  // Source until SourceEnd: https://datatracker.ietf.org/doc/html/rfc4634
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8' +
                                       'b605a43ff5bed8086072ba1e7cc2358baeca134c825a7';
  lDataRow.ExpectedOutputUTFStrTest := '9b7ce7c7af46e400a37c8099cb4bbb5d0408061dd74cdb5dac7' +
                                       '661bed1e53724bd07f299e265f400802a48d2e0b2092c';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa' +
                                       '08086e3b0f712fcc7c71a557e2db966c3e9fa91746039';
  lDataRow.ExpectedOutputUTFStrTest := '3c5fbafef52900a32840433c972999429d5c157426fdfb5c496' +
                                       '8278f25bd4fe4f3b7aee8ae060695b05f61e595609637';
  lDataRow.AddInputVector('abcdefghbcdefghicdefghijdefghij');
  lDataRow.AddInputVector('kefghijklfghijklmghijklmn');
  lDataRow.AddInputVector('hijklmnoijklmnopjklmnopqklmnopqrlmnopqr');
  lDataRow.AddInputVector('smnopqrstnopqrst');
  lDataRow.AddInputVector('u');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9d0e1809716474cb086e834e310a4a1ced149e9c00f24852' +
                                       '7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985';
  lDataRow.ExpectedOutputUTFStrTest := '85056c62b9b2eba33a1ea69d06e32e71715188b25d3f7a2b' +
                                       'c37be377890c4b0c08e7f55bc83550f0fe27a209088bc671';
  lDataRow.AddInputVector('a', 1, 1000000);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '2fc64a4f500ddb6828f6a3430b8dd72a368eb7f3a8322a70' +
                                       'bc84275b9c0b3ab00d27a5cc3c2d224aa6b61a0d79fb4596';
  lDataRow.ExpectedOutputUTFStrTest := 'e6ccec32ee864cb67b27155d65d4eefee73f4d9b21683f58' +
                                       'd066d44e3af4959016f31c107dbf3e8bc04bca3f35f3493f';
  lDataRow.AddInputVector('01234567012345670123456701234567', 1, 20);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c9a68443a005812256b8ec76b00516f0dbb74fab26d66591' +
                                       '3f194b6ffb0e91ea9967566b58109cbc675cc208e4c823f7';
  lDataRow.ExpectedOutputUTFStrTest := '9e1bc4e7cc69cd811ad22dcd6ea3666396571171c9585baa' +
                                       '490aa25a87dc17af6e648e814a4056454ed93caa28a53a8e';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\xa4\x1c\x49\x77\x79\xc0\x37\x5f\xf1\x0a' +
                                                '\x7f\x4e\x08\x59\x17\x39'));

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4f440db1e6edd2899fa335f09515aa025ee177a79f4b4aaf' +
                                       '38e42b5c4de660f5de8fb2a5b2fbd2a3cbffd20cff1288c0';
  lDataRow.ExpectedOutputUTFStrTest := '5e2efe090daef2acb31259391d0002f312b001784f1a8888' +
                                       '6fc133d97b14843fc564aa35b956ef37d967ad56a01b1c67';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\x39\x96\x69\xe2\x8f\x6b\x9c\x6d\xbc\xbb' +
                                                '\x69\x12\xec\x10\xff\xcf\x74\x79\x03\x49' +
                                                '\xb7\xdc\x8f\xbe\x4a\x8e\x7b\x3b\x56\x21' +
                                                '\xdb\x0f\x3e\x7d\xc8\x7f\x82\x32\x64\xbb' +
                                                '\xe4\x0d\x18\x11\xc9\xea\x20\x61\xe1\xc8' +
                                                '\x4a\xd1\x0a\x23\xfa\xc1\x72\x7e\x72\x02' +
                                                '\xfc\x3f\x50\x42\xe6\xbf\x58\xcb\xa8\xa2' +
                                                '\x74\x6e\x1f\x64\xf9\xb9\xea\x35\x2c\x71' +
                                                '\x15\x07\x05\x3c\xf4\xe5\x33\x9d\x52\x86' +
                                                '\x5f\x25\xcc\x22\xb5\xe8\x77\x84\xa1\x2f' +
                                                '\xc9\x61\xd6\x6c\xb6\xe8\x95\x73\x19\x9a' +
                                                '\x2c\xe6\x56\x5c\xbd\xf1\x3d\xca\x40\x38' +
                                                '\x32\xcf\xcb\x0e\x8b\x72\x11\xe8\x3a\xf3' +
                                                '\x2a\x11\xac\x17\x92\x9f\xf1\xc0\x73\xa5' +
                                                '\x1c\xc0\x27\xaa\xed\xef\xf8\x5a\xad\x7c' +
                                                '\x2b\x7c\x5a\x80\x3e\x24\x04\xd9\x6d\x2a' +
                                                '\x77\x35\x7b\xda\x1a\x6d\xae\xed\x17\x15' +
                                                '\x1c\xb9\xbc\x51\x25\xa4\x22\xe9\x41\xde' +
                                                '\x0c\xa0\xfc\x50\x11\xc2\x3e\xcf\xfe\xfd' +
                                                '\xd0\x96\x76\x71\x1c\xf3\xdb\x0a\x34\x40' +
                                                '\x72\x0e\x16\x15\xc1\xf2\x2f\xbc\x3c\x72' +
                                                '\x1d\xe5\x21\xe1\xb9\x9b\xa1\xbd\x55\x77' +
                                                '\x40\x86\x42\x14\x7e\xd0\x96'));
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cdbb41d1164ef06788b8b3f0fcb157de981311f0bc76752c952' +
                                       '075fcb14d1c133b27ddc7ad6b6b8c180346d0fe18694b';
  lDataRow.ExpectedOutputUTFStrTest := '2cbf89df082d30f912fc15415e3e0ee75cf2d5ebdd2b32626d6' +
                                       'a94ff86e40c68cce673c5a28b59a1ab5f879d11698bdb';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity '+
                          'decision error. It has total length 111 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '49b8d662fc136462591f9a96a64d28ea8fb03b7b943dd3400f2' +
                                       '633effcab37502927736f19bdeecce842801f41ab3e26';
  lDataRow.ExpectedOutputUTFStrTest := '32a077958cdd604f0224941d17c52b37d441152ab0b19bf7594' +
                                       '50f39a3c94f1d8521c20e5add06cbb5f56082265f43c5';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity '+
                          'decision error. It has total length 112 bytes.');
end;

procedure TestTHash_SHA384.TestDigestSize;
begin
  CheckEquals(48, FHash.DigestSize);
end;

procedure TestTHash_SHA384.TestIdentity;
begin
  CheckEquals($C4858567, FHash.Identity);
end;

procedure TestTHash_SHA384.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_SHA384.TestBlockSize;
begin
  CheckEquals(128, FHash.BlockSize);
end;

procedure TestTHash_SHA384.TestClassByName;
begin
  DoTestClassByName('THash_SHA384', THash_SHA384);
end;

procedure TestTHash_SHA512.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_SHA512.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f' +
                                       '4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931' +
                                       'bd47417a81a538327af927da3e';
  lDataRow.ExpectedOutputUTFStrTest := 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f' +
                                       '4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931' +
                                       'bd47417a81a538327af927da3e';
  lDataRow.AddInputVector('');


  // Source until SourceEnd: https://datatracker.ietf.org/doc/html/rfc4634
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9' +
                                       'eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d44' +
                                       '23643ce80e2a9ac94fa54ca49f';
  lDataRow.ExpectedOutputUTFStrTest := 'add8b8154df7a734d2947a981f4e61c5366710d610040e5b548' +
                                       '94d1006e89283cba082287ed5dd4c25cdaa5af56d24ab9fbedc' +
                                       '56897130b0b5f3e50c7f9ee6df';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa1729' +
                                       '9aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329' +
                                       'eeb6dd26545e96e55b874be909';
  lDataRow.ExpectedOutputUTFStrTest := 'd14cbc5ecfd355acf9d181ee878b91db4f30a7b03f7904388f2' +
                                       '52a77b1fffa9feb96803698294556ff7ce87ad0ab3ae748df97' +
                                       '9603733105ff3ac038e51483a3';
  lDataRow.AddInputVector('abcdefghbcdefghicdefghijdefghij');
  lDataRow.AddInputVector('kefghijklfghijklmghijklmn');
  lDataRow.AddInputVector('hijklmnoijklmnopjklmnopqklmnopqrlmnopqr');
  lDataRow.AddInputVector('smnopqrstnopqrst');
  lDataRow.AddInputVector('u');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e718483d0ce769644e2e42c7bc15b4638e1f98b13b204428' +
                                       '5632a803afa973ebde0ff244877ea60a4cb0432ce577c31b' +
                                       'eb009c5c2c49aa2e4eadb217ad8cc09b';
  lDataRow.ExpectedOutputUTFStrTest := '5e6b9aa02688b69fe5ebe842aeab69b22144d815ca603051' +
                                       'f2e61ab752d202f85dc54252d19f9d62381a2d5e88ab391b' +
                                       '7c6565d5e0d39925a4ad5b07e99925bd';
  lDataRow.AddInputVector('a', 1, 1000000);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '89d05ba632c699c31231ded4ffc127d5a894dad412c0e024' +
                                       'db872d1abd2ba8141a0f85072a9be1e2aa04cf33c765cb51' +
                                       '0813a39cd5a84c4acaa64d3f3fb7bae9';
  lDataRow.ExpectedOutputUTFStrTest := '11c3e27d770153716741eb4d62ea4ae8e8796849e70deddf' +
                                       '7333e41de50ba8123e7500bf606a7f05794d4aad5c794ae2' +
                                       '0a9eba1cb33cdf69eb7e92b225f58804';
  lDataRow.AddInputVector('01234567012345670123456701234567', 1, 20);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cb0b67a4b8712cd73c9aabc0b199e9269b20844afb75acbd' +
                                       'd1c153c9828924c3ddedaafe669c5fdd0bc66f630f677398' +
                                       '8213eb1b16f517ad0de4b2f0c95c90f8';
  lDataRow.ExpectedOutputUTFStrTest := 'c9f285c82c84e25c22034a5ffc8bc14626b94bf1770cd83b' +
                                       '5c0744b27f56758f304271dc3676b7a8ba82b9af0c51b886' +
                                       '6461f301ecdf52796d061dc118776f10';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91'+
                                                '\x81\x6e\x9d\x98\xbf\xf0\xa0'));

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c665befb36da189d78822d10528cbf3b12b3eef726039909' +
                                       'c1a16a270d48719377966b957a878e720584779a62825c18' +
                                       'da26415e49a7176a894e7510fd1451f5';
  lDataRow.ExpectedOutputUTFStrTest := '131e7e4a7b3b24152f67680d6e168d6e6973aeb0baf71acd' +
                                       '2d1071dc48bf623e7b3bf965df0a6b1b8b893376e41e2ae1' +
                                       '74019d5f682d05de2db0865af5ca61d3';
  lDataRow.AddInputVector(TFormat_ESCAPE.Decode('\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80' +
                                                '\x7a\x50\x2d\x65\x82\x4e\x31\xa2\x30' +
                                                '\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8' +
                                                '\xd8\x4e\x0d\xe1\xde\x69\x74\xbf\x49' +
                                                '\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5' +
                                                '\x8c\x26\xc4\x93\x60\xc3\xe8\x7a\xf5' +
                                                '\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f' +
                                                '\xf2\xf8\x68\x00\x2b\xc3\xe4\x31\xed' +
                                                '\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3\xb2' +
                                                '\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69' +
                                                '\x4f\xcb\xba\xf8\x8d\x95\x19\xe4\xeb' +
                                                '\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea' +
                                                '\x95\xbc\x44\x65\xc8\x82\x1a\xac\xd2' +
                                                '\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d' +
                                                '\xc3\x2f\x96\x90\x87\xa1\x45\xb0\xd9' +
                                                '\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41' +
                                                '\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac' +
                                                '\xe6\x34\x06\x4e\x6d\x99\x28\x35\x13' +
                                                '\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e' +
                                                '\x9a\x0d\xc6\xd3\xb1\xf8\xb2\x46\xf1' +
                                                '\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb' +
                                                '\x20\x98\xe8\xbf\x16\xf2\x68\xd6\x4f' +
                                                '\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79' +
                                                '\x1b\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51' +
                                                '\x86\x3a\x96\xc9\x49\xad\x47\xd7\xfb' +
                                                '\x40\xd2'));
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b4dd09998c54420c9445fb0706715f595435880da13fc56d2f5' +
                                       '5b47a86cd9e59a5ee9564f3bc8e91ed9ab6b2a5db2561a3bd56' +
                                       'e21defda4faf831da96210104d';
  lDataRow.ExpectedOutputUTFStrTest := 'a3c375fd0d3c264e4197cb4a7087e854d487c1d6e1011408b3d' +
                                       'a60e48d51596c950566215cf8bc917354862c7de4e38f155aed' +
                                       '1ee9f3f3416c5364782a534ac2';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. It has total length 111 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ad80509dcad277f40647311294f9b007165ae8456829d4befdf' +
                                       'd0de536c05c8ceec7dbe6d9dac88578fa3037d37b81382c0ae1' +
                                       '4c2fd9388fde50105ad1d7d993';
  lDataRow.ExpectedOutputUTFStrTest := 'f5fd5871f5d7c55b230fae0d48d054dd6732aa35a0b72074721' +
                                       'b3a28fb685ed5560dad9864a35c16f237696666503bada6cc77' +
                                       '082258f65f265c501b31dcf92b';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. It has total length 112 bytes.');

end;

procedure TestTHash_SHA512.TestDigestSize;
begin
  CheckEquals(64, FHash.DigestSize);
end;

procedure TestTHash_SHA512.TestIdentity;
begin
  CheckEquals($F8A9E7A9, FHash.Identity);
end;

procedure TestTHash_SHA512.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_SHA512.TestBlockSize;
begin
  CheckEquals(128, FHash.BlockSize);
end;

procedure TestTHash_SHA512.TestClassByName;
begin
  DoTestClassByName('THash_SHA512', THash_SHA512);
end;

{ TestTHash_HavalBase }

procedure TestTHash_Haval128.TestSetRoundsMax;
var
  Hash : THash_Haval128;
begin
  Hash := FHash as THash_Haval128;

  Hash.Rounds := Hash.GetMinRounds;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := 3;
  CheckEquals(3, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds + 1;
  CheckEquals(3, Hash.Rounds);
end;

procedure TestTHash_Haval128.TestSetRoundsMin;
var
  Hash : THash_Haval128;
begin
  Hash := FHash as THash_Haval128;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds - 1;
  CheckEquals(3, Hash.Rounds);
end;

{ TestTHash_Haval128 }

procedure TestTHash_Haval128.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Haval128.Create;

  // Source until SourceEnd: https://web.archive.org/web/20120206072234/http://
  // Rounds: 3               labs.calyptix.com/haval-1.1.tar.gz
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c68f39913f901f3ddf44c707357a7d70';
  lDataRow.ExpectedOutputUTFStrTest := 'c68f39913f901f3ddf44c707357a7d70';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0cd40739683e15f01ca5dbceef4059f1';
  lDataRow.ExpectedOutputUTFStrTest := 'f2ac5ac2aae01fc184ef399da42d5865';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'dc1f3c893d17cc4edd9ae94af76a0af0';
  lDataRow.ExpectedOutputUTFStrTest := 'b0b47bdc3c2434256b49c77675bd0aab';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd4be2164ef387d9f4d46ea8efb180cf5';
  lDataRow.ExpectedOutputUTFStrTest := 'a74975d492868f80184a785e163d6a1a';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'dc502247fb3eb8376109eda32d361d82';
  lDataRow.ExpectedOutputUTFStrTest := '6f2851b51a880c8d725dbddcc7274382';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'de5eb3f7d9eb08fae7a07d68e3047ec6';
  lDataRow.ExpectedOutputUTFStrTest := 'f68c39679f1660c0504feaa4d5958587';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4806b64dae93d3606308310a439e2a3a';
  lDataRow.ExpectedOutputUTFStrTest := 'dc48ac538e085f81571d4a64aca44fe4';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8beaa7dd5bb591c8009e429d79041813';
  lDataRow.ExpectedOutputUTFStrTest := '7669b7e0b3a872b8f4f48c5351c4c9c5';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8beaa7dd5bb591c8009e429d79041813';
  lDataRow.ExpectedOutputUTFStrTest := '7669b7e0b3a872b8f4f48c5351c4c9c5';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1bdc556b29ad02ec09af8c66477f2a87';
  lDataRow.ExpectedOutputUTFStrTest := '1bdc556b29ad02ec09af8c66477f2a87';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '24d2bc955a219e3e06462c91b555cfa1';
  lDataRow.ExpectedOutputUTFStrTest := 'fa53172579efb3ba63cf4b32e4f66bdd';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('a');


  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '16c743e5eefd3266ed50deac6c30313e';
  lDataRow.ExpectedOutputUTFStrTest := 'c0716b442299437c01885a4e6335b2c2';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '82d163440f6e853229a97007ec4af0e5';
  lDataRow.ExpectedOutputUTFStrTest := '9eb5e08841eb1cdab920d91660339340';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '92e8ec9ad7fd209d97e9ce21b50440e9';
  lDataRow.ExpectedOutputUTFStrTest := '0389809978badf696ea0290488be3ddd';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4ae2f37cef9275cce0d73f6a1eb9cdd8';
  lDataRow.ExpectedOutputUTFStrTest := '821ea5eb3f12c7cb429eb4f44c60112c';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3e1846cda3c9542944672b7150d0f38c';
  lDataRow.ExpectedOutputUTFStrTest := '67c7f95b227d60218508df6c7b4b9fe2';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '41b74ec225c9fb7a8e24840a98141b39';
  lDataRow.ExpectedOutputUTFStrTest := '85b87eb2cfdf9dc3e6bf25b654c28f5c';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '41b74ec225c9fb7a8e24840a98141b39';
  lDataRow.ExpectedOutputUTFStrTest := '85b87eb2cfdf9dc3e6bf25b654c28f5c';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  // Self generated variants with different rounds
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ee6bbf4d6a46a679b3a856c88538bb98';
  lDataRow.ExpectedOutputUTFStrTest := 'ee6bbf4d6a46a679b3a856c88538bb98';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5cd07f03330c3b5020b29ba75911e17d';
  lDataRow.ExpectedOutputUTFStrTest := '972ebb528aa1d753cd2e9cbcbb4b1bc5';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '184b8482a0c050dca54b59c7f05bf5dd';
  lDataRow.ExpectedOutputUTFStrTest := '184b8482a0c050dca54b59c7f05bf5dd';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f23fbe704be8494bfa7a7fb4f8ab09e5';
  lDataRow.ExpectedOutputUTFStrTest := 'cb0c4214d3cf2739e60db8c453df8aca';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');
end;

procedure TestTHash_Haval128.TestDigestSize;
begin
  CheckEquals(16, FHash.DigestSize);
end;

procedure TestTHash_Haval128.TestGetMaxRounds;
begin
  CheckEquals(5, THash_Haval128(FHash).GetMaxRounds);
end;

procedure TestTHash_Haval128.TestGetMinRounds;
begin
  CheckEquals(3, THash_Haval128(FHash).GetMinRounds);
end;

procedure TestTHash_Haval128.TestIdentity;
begin
  CheckEquals($B0837E88, FHash.Identity);
end;

procedure TestTHash_Haval128.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Haval128.TestBlockSize;
begin
  CheckEquals(128, FHash.BlockSize);
end;

procedure TestTHash_Haval128.TestClassByName;
begin
  DoTestClassByName('THash_Haval128', THash_Haval128);
end;

procedure TestTHash_Haval160.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Haval160.Create;

  // Source until SourceEnd: https://web.archive.org/web/20120206072234/http://
  // Rounds: 3               labs.calyptix.com/haval-1.1.tar.gz
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd353c3ae22a25401d257643836d7231a9a95f953';
  lDataRow.ExpectedOutputUTFStrTest := 'd353c3ae22a25401d257643836d7231a9a95f953';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4da08f514a7275dbc4cece4a347385983983a830';
  lDataRow.ExpectedOutputUTFStrTest := 'd976681ea27160c08ebab0032a76653fae848376';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8822bc6f3e694e73798920c77ce3245120dd8214';
  lDataRow.ExpectedOutputUTFStrTest := 'cb5a03288450a452caec0e9154cb56ccaa007361';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'be68981eb3ebd3f6748b081ee5d4e1818f9ba86c';
  lDataRow.ExpectedOutputUTFStrTest := '5433add25965d4cef4158530ea11d9cabf5dfae0';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'eba9fa6050f24c07c29d1834a60900ea4e32e61b';
  lDataRow.ExpectedOutputUTFStrTest := '4461ef31738d14dca0ad4419f5421c50b05310d3';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '97dc988d97caae757be7523c4e8d4ea63007a4b9';
  lDataRow.ExpectedOutputUTFStrTest := 'e7052bbd65c7608cf0589f6471d85d7c0f02a6fd';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ba27e0d51b9ba140804252413c52b42dfe97214b';
  lDataRow.ExpectedOutputUTFStrTest := '1eecea4c278e9a797bbcfce396dcebca7243623b';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block '+
                          'necessity decision error. For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5ea7fa9a0236aad66a1da8f161985c6e3dae2b81';
  lDataRow.ExpectedOutputUTFStrTest := 'b0de8db36f55ea32b57d4333114d4a9d47ce53cd';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5ea7fa9a0236aad66a1da8f161985c6e3dae2b81';
  lDataRow.ExpectedOutputUTFStrTest := 'b0de8db36f55ea32b57d4333114d4a9d47ce53cd';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'fe79d0a044ffb75d5354668d664e4f4b9cc33477';
  lDataRow.ExpectedOutputUTFStrTest := 'fe79d0a044ffb75d5354668d664e4f4b9cc33477';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5e1610fced1d3adb0bb18e92ac2b11f0bd99d8ed';
  lDataRow.ExpectedOutputUTFStrTest := '871624bcbb8c01039b10dbd18f4e85ef2847beec';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8e568ad6ccd58d17e0a11e92183232e0d1d2e9bf';
  lDataRow.ExpectedOutputUTFStrTest := '53374669cfde8f3a5013ff3ba218ce84d4fe0764';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '700d43a9b5e38300303fd4e25a6a326beb4a2241';
  lDataRow.ExpectedOutputUTFStrTest := '92acab606db474de51c93cb812b125f0a71c413b';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1dd40aeab9610585fcae7492ff3b893c2a018f4e';
  lDataRow.ExpectedOutputUTFStrTest := '93cc27c8f8e834a0ecc86f7e15dd25eddc4439f5';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '485abb76ed2f5ac8bb86ddeb8cb4c54cf5bb077b';
  lDataRow.ExpectedOutputUTFStrTest := '82424bfabb7afd551fb01478e0bc26099300cd1b';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7e3ec827726ae5ce4f4f67614395aa1c0602551a';
  lDataRow.ExpectedOutputUTFStrTest := '297a10aab083211007ffa25be84fcfdb9cb8a94d';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block '+
                          'necessity decision error. For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '687e9073f7ec5f01ea4744b86ef40e13aaacf0a4';
  lDataRow.ExpectedOutputUTFStrTest := 'd65ef2dcb081c97494e84407033cb29415a80730';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '687e9073f7ec5f01ea4744b86ef40e13aaacf0a4';
  lDataRow.ExpectedOutputUTFStrTest := 'd65ef2dcb081c97494e84407033cb29415a80730';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  // Self generated variants with different rows
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1d33aae1be4146dbaaca0b6e70d7a11f10801525';
  lDataRow.ExpectedOutputUTFStrTest := '1d33aae1be4146dbaaca0b6e70d7a11f10801525';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e0a5be29627332034d4dd8a910a1a0e6fe04084d';
  lDataRow.ExpectedOutputUTFStrTest := '441d327d5d29815bacf33565a73430843ed4a87e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '255158cfc1eed1a7be7c55ddd64d9790415b933b';
  lDataRow.ExpectedOutputUTFStrTest := '255158cfc1eed1a7be7c55ddd64d9790415b933b';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f5147df7abc5e3c81b031268927c2b5761b5a2b5';
  lDataRow.ExpectedOutputUTFStrTest := '00eb3b4c72b8d6ac5f99332c40208de1af44760b';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');
end;

procedure TestTHash_Haval160.TestDigestSize;
begin
  CheckEquals(20, FHash.DigestSize);
end;

procedure TestTHash_Haval160.TestGetMaxRounds;
begin
  CheckEquals(5, THash_Haval160(FHash).GetMaxRounds);
end;

procedure TestTHash_Haval160.TestGetMinRounds;
begin
  CheckEquals(3, THash_Haval160(FHash).GetMinRounds);
end;

procedure TestTHash_Haval160.TestIdentity;
begin
  CheckEquals($DA3433BE, FHash.Identity);
end;

procedure TestTHash_Haval160.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Haval160.TestSetRoundsMax;
var
  Hash : THash_Haval160;
begin
  Hash := FHash as THash_Haval160;

  Hash.Rounds := Hash.GetMinRounds;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := 3;
  CheckEquals(3, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds + 1;
  CheckEquals(3, Hash.Rounds);
end;

procedure TestTHash_Haval160.TestSetRoundsMin;
var
  Hash : THash_Haval160;
begin
  Hash := FHash as THash_Haval160;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds - 1;
  CheckEquals(3, Hash.Rounds);
end;

procedure TestTHash_Haval160.TestBlockSize;
begin
  CheckEquals(128, FHash.BlockSize);
end;

procedure TestTHash_Haval160.TestClassByName;
begin
  DoTestClassByName('THash_Haval160', THash_Haval160);
end;

procedure TestTHash_Haval192.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Haval192.Create;

  // Source until SourceEnd: https://web.archive.org/web/20120206072234/http://
  // Rounds: 4               labs.calyptix.com/haval-1.1.tar.gz
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4a8372945afa55c7dead800311272523ca19d42ea47b72da';
  lDataRow.ExpectedOutputUTFStrTest := '4a8372945afa55c7dead800311272523ca19d42ea47b72da';
  lDataRow.AddInputVector('');
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '856c19f86214ea9a8a2f0c4b758b973cce72a2d8ff55505c';
  lDataRow.ExpectedOutputUTFStrTest := 'ea49939cb5a812d962cb3593dd37e35cdcd208961be61bf5';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0c1396d7772689c46773f3daaca4efa982adbfb2f1467eea';
  lDataRow.ExpectedOutputUTFStrTest := '5eb34e664e18f78da615ab3424243c49b054af95722509e8';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c3a5420bb9d7d82a168f6624e954aaa9cdc69fb0f67d785e';
  lDataRow.ExpectedOutputUTFStrTest := 'ca16d8d258a68bb8443fe6185558e44f34ddad8ba86199e0';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '2e2e581d725e799fda1948c75e85a28cfe1cf0c6324a1ada';
  lDataRow.ExpectedOutputUTFStrTest := '368df8981494d39560453be6860b2290eced3cf8087d4147';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e5c9f81ae0b31fc8780fc37cb63bb4ec96496f79a9b58344';
  lDataRow.ExpectedOutputUTFStrTest := 'd1458c150e3330016f0ebdb1f7003e0eba960739a6830923';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8c80602a16fcca8332c08446ea61a2fbc74e05d3361f0e4d';
  lDataRow.ExpectedOutputUTFStrTest := '517f983928861f8a86402101e500fb613070177cfc93914c';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity '+
                          'decision error. For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aa15056802a32823332dd551ebe3e39918d6bc9e1fa293b1';
  lDataRow.ExpectedOutputUTFStrTest := '80c428dfb6bc4179803c47f840a98ffeb527b491b06cdfd6';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aa15056802a32823332dd551ebe3e39918d6bc9e1fa293b1';
  lDataRow.ExpectedOutputUTFStrTest := '80c428dfb6bc4179803c47f840a98ffeb527b491b06cdfd6';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '51fa9e28c96865207ed6dae2eaa1d8af6e7de2783ebec4b4';
  lDataRow.ExpectedOutputUTFStrTest := '51fa9e28c96865207ed6dae2eaa1d8af6e7de2783ebec4b4';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a1446e6cedb4b28bc6e13d4d1d2694e9ce4a3d942c73589e';
  lDataRow.ExpectedOutputUTFStrTest := '157776b815376afdba30a5de81cb2c3eaa6d28ed7b19bbad';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '74aa31182ff09bcce453a7f71b5a7c5e80872fa90cd93ae4';
  lDataRow.ExpectedOutputUTFStrTest := '056003283fb434178a1ff76764812885196cdc74604c967b';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ca05546ffa4b69dafa7c04424cc10802a2523efcb8bebb61';
  lDataRow.ExpectedOutputUTFStrTest := '2d95bdbb37c3c74118c739030345f0acd66551b3cd6486d7';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5a238735d9e902e16cad81229cc981a763508c73f4a52dd0';
  lDataRow.ExpectedOutputUTFStrTest := '3dc4298f38dced830191e2d6aa012304ddba79dbad83cd05';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd51d73eb03b0d841c24f2007aa9159f0f70a971cbfbed33c';
  lDataRow.ExpectedOutputUTFStrTest := 'cfcd7add4233885ec083a5a25662b29afbcbbcb4e6f081c7';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1cee084b711ef399076a4cfa095a81dc6e1667f3c8207204';
  lDataRow.ExpectedOutputUTFStrTest := '6e2c2b45cc4efd0422ae3a6c0cf4dc9a400a901723881733';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity '+
                          'decision error. For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f5608294798348bfa3fc45f72954a0e980b15804b4c56674';
  lDataRow.ExpectedOutputUTFStrTest := 'ff7c15641ca292000ba31bb863b7f3b524943e2ed64c4b12';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f5608294798348bfa3fc45f72954a0e980b15804b4c56674';
  lDataRow.ExpectedOutputUTFStrTest := 'ff7c15641ca292000ba31bb863b7f3b524943e2ed64c4b12';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  // Self generated variants with different rows
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85';
  lDataRow.ExpectedOutputUTFStrTest := '4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5ffa3b3548a6e2cfc06b7908ceb5263595df67cf9c4b9341';
  lDataRow.ExpectedOutputUTFStrTest := 'f7a1cd5310024e2f8aa48e1240011cd0c60961e9b7286039';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');
end;

procedure TestTHash_Haval192.TestDigestSize;
begin
  CheckEquals(24, FHash.DigestSize);
end;

procedure TestTHash_Haval192.TestGetMaxRounds;
begin
  CheckEquals(5, THash_Haval192(FHash).GetMaxRounds);
end;

procedure TestTHash_Haval192.TestGetMinRounds;
begin
  CheckEquals(4, THash_Haval192(FHash).GetMinRounds);
end;

procedure TestTHash_Haval192.TestIdentity;
begin
  CheckEquals($B3A24E5D, FHash.Identity);
end;

procedure TestTHash_Haval192.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Haval192.TestSetRoundsMax;
var
  Hash : THash_Haval192;
begin
  Hash := FHash as THash_Haval192;

  Hash.Rounds := Hash.GetMinRounds;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := 3;
  CheckEquals(4, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds + 1;
  CheckEquals(4, Hash.Rounds);
end;

procedure TestTHash_Haval192.TestSetRoundsMin;
var
  Hash : THash_Haval192;
begin
  Hash := FHash as THash_Haval192;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds - 1;
  CheckEquals(4, Hash.Rounds);
end;

procedure TestTHash_Haval192.TestBlockSize;
begin
  CheckEquals(128, FHash.BlockSize);
end;

procedure TestTHash_Haval192.TestClassByName;
begin
  DoTestClassByName('THash_Haval192', THash_Haval192);
end;

procedure TestTHash_Haval224.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Haval224.Create;

  // Source until SourceEnd: https://web.archive.org/web/20120206072234/http://
  // Rounds: 4               labs.calyptix.com/haval-1.1.tar.gz
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e';
  lDataRow.ExpectedOutputUTFStrTest := '3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '742f1dbeeaf17f74960558b44f08aa98bdc7d967e6c0ab8f799b3ac1';
  lDataRow.ExpectedOutputUTFStrTest := '949b0e1c272fad467366c614cb79c878f648363c6e34e4a6af2bf0c9';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '85538ffc06f3b1c693c792c49175639666f1dde227da8bd000c1e6b4';
  lDataRow.ExpectedOutputUTFStrTest := 'c731136eca1d43c14c0fa34544776e06f1a911ebd245a7ae4cd6624d';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bebd7816f09baeecf8903b1b9bc672d9fa428e462ba699f814841529';
  lDataRow.ExpectedOutputUTFStrTest := '97c760aec423f4f0d4fab68e0ea57ca00a402ca258c41495bf396337';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a0ac696cdb2030fa67f6cc1d14613b1962a7b69b4378a9a1b9738796';
  lDataRow.ExpectedOutputUTFStrTest := '03973c5c75dcc59f28d7b7798ebe75a9cc4d6d14316ac615e8d9977c';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3e63c95727e0cd85d42034191314401e42ab9063a94772647e3e8e0f';
  lDataRow.ExpectedOutputUTFStrTest := '09293b232655058426832f0ceb13ff041688f4fa43243b66a2c19677';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'adf788362468585753a4ebb59c44c8934d2995c6305beb9345ddf485';
  lDataRow.ExpectedOutputUTFStrTest := '0f4b666b0257088fe15e05a8b738c9bb7955b62369df9994b92049fe';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity '+
                          'decision error. For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0d53e2e5e768707ab94070f6f9b8accd9ad831076780443a2e659fdc';
  lDataRow.ExpectedOutputUTFStrTest := 'e0d9ddda7cbdcde1ae543990fc5462193140b97c82646ce9379d751c';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0d53e2e5e768707ab94070f6f9b8accd9ad831076780443a2e659fdc';
  lDataRow.ExpectedOutputUTFStrTest := 'e0d9ddda7cbdcde1ae543990fc5462193140b97c82646ce9379d751c';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aacd8950b239b05e8a40a0419afd3bbed206623913d8a6dfe71d174b';
  lDataRow.ExpectedOutputUTFStrTest := 'aacd8950b239b05e8a40a0419afd3bbed206623913d8a6dfe71d174b';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '54a26096c951725228d34a1b55c2db5c28446e6b243fe2ae78623a4b';
  lDataRow.ExpectedOutputUTFStrTest := 'a4575897b531c3e05a50f950639c47b65ec5e4047af26410773aeb52';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f9040eebae11709245501beffb5fb849f88a9086f24df3a55a03a01a';
  lDataRow.ExpectedOutputUTFStrTest := '4eaeb545094367efa73ad92f0c4eff66d3ed8ad57c125bbfe4f98c74';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '144cb2de11f05df7c356282a3b485796da653f6b702868c7dcf4ae76';
  lDataRow.ExpectedOutputUTFStrTest := 'c2762d3cfced507c48dd8e0827cffb020c26239cd8fcebcd65ddadb7';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'fbb63f06592fb9aa4f59652b99bc53c1ff72675726c71326c682dabc';
  lDataRow.ExpectedOutputUTFStrTest := 'b8cd24f40b7a9f3ba95e5249b1fdb61df93090f85fb50973ccab8c4c';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1120b26105044df0b4e5b904705f3b8cbbc14a52b73301c300baff8a';
  lDataRow.ExpectedOutputUTFStrTest := 'e427422e29d14a7371874ebc3e3b04ab96766954074c8e7345b6fa10';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '752a1ee3fc2185888a421e148d6a3b8fb33ac20ba0668598c11d755a';
  lDataRow.ExpectedOutputUTFStrTest := '4ead6b5944f5453f9f8abf9c863687ac0e7d6b5906d8334f5f334b38';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity '+
                          'decision error. For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aff21cea7b3294dd02e6de843650fe82eb51cdd1e9d8873b13834717';
  lDataRow.ExpectedOutputUTFStrTest := 'ece302f7e317c2bbab56f1e29ac123441a241297f5696465f8b7ed6d';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aff21cea7b3294dd02e6de843650fe82eb51cdd1e9d8873b13834717';
  lDataRow.ExpectedOutputUTFStrTest := 'ece302f7e317c2bbab56f1e29ac123441a241297f5696465f8b7ed6d';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  // Self generated variants with different rows
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e';
  lDataRow.ExpectedOutputUTFStrTest := '4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '67b3cb8d4068e3641fa4f156e03b52978b421947328bfb9168c7655d';
  lDataRow.ExpectedOutputUTFStrTest := '388826fda119989238a74d9c4a146d699a16f774c0f2c3d503114e6f';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');
end;

procedure TestTHash_Haval224.TestDigestSize;
begin
  CheckEquals(28, FHash.DigestSize);
end;

procedure TestTHash_Haval224.TestGetMaxRounds;
begin
  CheckEquals(5, THash_Haval224(FHash).GetMaxRounds);
end;

procedure TestTHash_Haval224.TestGetMinRounds;
begin
  CheckEquals(4, THash_Haval224(FHash).GetMinRounds);
end;

procedure TestTHash_Haval224.TestIdentity;
begin
  CheckEquals($BB738CFA, FHash.Identity);
end;

procedure TestTHash_Haval224.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Haval224.TestSetRoundsMax;
var
  Hash : THash_Haval224;
begin
  Hash := FHash as THash_Haval224;

  Hash.Rounds := Hash.GetMinRounds;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := 4;
  CheckEquals(4, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds + 1;
  CheckEquals(4, Hash.Rounds);
end;

procedure TestTHash_Haval224.TestSetRoundsMin;
var
  Hash : THash_Haval224;
begin
  Hash := FHash as THash_Haval224;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds;
  CheckEquals(4, Hash.Rounds);

  Hash.Rounds := 5;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds - 1;
  CheckEquals(4, Hash.Rounds);
end;

procedure TestTHash_Haval224.TestBlockSize;
begin
  CheckEquals(128, FHash.BlockSize);
end;

procedure TestTHash_Haval224.TestClassByName;
begin
  DoTestClassByName('THash_Haval224', THash_Haval224);
end;

procedure TestTHash_Haval256.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Haval256.Create;

  // Source until SourceEnd: https://web.archive.org/web/20120206072234/http://
  // Rounds: 5               labs.calyptix.com/haval-1.1.tar.gz
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330';
  lDataRow.ExpectedOutputUTFStrTest := 'be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'de8fd5ee72a5e4265af0a756f4e1a1f65c9b2b2f47cf17ecf0d1b88679a3e22f';
  lDataRow.ExpectedOutputUTFStrTest := '42f59f1483a46c33f1d8c19a2b3bfafc5ad8855b6be91f02b1238476764c709f';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '153d2c81cd3c24249ab7cd476934287af845af37f53f51f5c7e2be99ba28443f';
  lDataRow.ExpectedOutputUTFStrTest := '3c94e3e4c74a5c873d8f9a12636ec216ff0b8033e03ec6e584ff4c3d294a86db';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '357e2032774abbf5f04d5f1dec665112ea03b23e6e00425d0df75ea155813126';
  lDataRow.ExpectedOutputUTFStrTest := 'f4abfc9b62f537b3d525b91f05653ef6ee439896921256aaf5f6e808172fad38';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c9c7d8afa159fd9e965cb83ff5ee6f58aeda352c0eff005548153a61551c38ee';
  lDataRow.ExpectedOutputUTFStrTest := '7d4093dcdac779c9e9e2598f70b0ba8d64fb091b6af7c499348676ffd3611334';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('cdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b45cb6e62f2b1320e4f8f1b0b273d45add47c321fd23999dcf403ac37636d963';
  lDataRow.ExpectedOutputUTFStrTest := '41cf38ae494b0ff1edc06d99b5085026a057da244a4f62f5882a71cadf6b9054';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg');
  lDataRow.AddInputVector('hijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '42bb773476b0e978e7fa7414b2e7ecf0dc0a2accb96ade5d815d0e4706969272';
  lDataRow.ExpectedOutputUTFStrTest := 'acff80b9410d5116f98979c2440c3fdb0337279cb19971f7946958628d2178fc';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899876543210', 2);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e7467dad3b4f59c182a7869816ec15c8b59e4c5038ff5afbff60e6d44041a670';
  lDataRow.ExpectedOutputUTFStrTest := '982f54d460ebe0221fd30391c0b58d139ef98335ffb5ba4551a4cd4b7fb9596e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. '+
                          'For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3f2be6dd53dc7944290e8939192bcccc8077c99b622e0c20355942dd6a4ec009';
  lDataRow.ExpectedOutputUTFStrTest := '8a408f644a207606c853c4b297cf4b1b2768e91ab5b8ef6ce7c6a6c2cc1b056e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3f2be6dd53dc7944290e8939192bcccc8077c99b622e0c20355942dd6a4ec009';
  lDataRow.ExpectedOutputUTFStrTest := '8a408f644a207606c853c4b297cf4b1b2768e91ab5b8ef6ce7c6a6c2cc1b056e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5981d3f8cce7f5674752595f4ad24c184ba1c738c986d4d2eddf2bd86c3f8679';
  lDataRow.ExpectedOutputUTFStrTest := '5981d3f8cce7f5674752595f4ad24c184ba1c738c986d4d2eddf2bd86c3f8679';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '166f2218e0994a78ebad3feab0211b612b14e93e5cceb60e6f143df0fa166d39';
  lDataRow.ExpectedOutputUTFStrTest := '8e7ae4af7207e8599142d23d097de42d9f7b5bd314de95261eff46d305834157';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '217bfdf84f5c775596c2f13ceea7417cd4e198d53ca24902f9717585ec5789ac';
  lDataRow.ExpectedOutputUTFStrTest := '45e7e26a86f323b0fe52aecb5a354f683b0685aaf0a99d326baa56117bf60368';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('HAVAL');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a6828eeb82d5a9cbfc7c522ad4b3c38a42753deceb20fb3a6fabc0da8ccd6a1a';
  lDataRow.ExpectedOutputUTFStrTest := '835505ef404be97dde1bcaf354cab1e88282bb2c03bb973ea80dc323033b64d3';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1a1dc8099bdaa7f35b4da4e805f1a28fee909d8dee920198185cbcaed8a10a8d';
  lDataRow.ExpectedOutputUTFStrTest := '1722c5dc88d77708d4787d283d7e263857e984ae5a6f9a1854963906343abbf8';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('cdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c5647fc6c1877fff96742f27e9266b6874894f41a08f5913033d9d532aeddb39';
  lDataRow.ExpectedOutputUTFStrTest := '60811e064a010c9324c386084e7e386dc7371276571d6ba4ff38495ea68cd90c';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg');
  lDataRow.AddInputVector('hijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '88c8334686f5ae277de90a2267c7e52ec6e2fe708eedb067d136e046613f2253';
  lDataRow.ExpectedOutputUTFStrTest := 'd4e9a56083f2bf6ec457b646698df7357017c53b58f0732d517796d69d057f53';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899876543210', 2);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7da3e3411ae031fa241e6f2f7deaf62827e8e97a2865ce5c1b67da2b6065efe4';
  lDataRow.ExpectedOutputUTFStrTest := '1dd3aaf5bc03f3674732a28523f57ed24208d283e3836e5900ec8db0833b3f1c';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. '+
                          'For this detection it is 117 bytes.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6d0efcb27421a2c45c14dd66f5de5e289893360ca2089c26ef491c01bd94b21a';
  lDataRow.ExpectedOutputUTFStrTest := 'e42666d73cee62653aecbce6b1bbf76134bf441f8fb04ac7be826bc2493cd537';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6d0efcb27421a2c45c14dd66f5de5e289893360ca2089c26ef491c01bd94b21a';
  lDataRow.ExpectedOutputUTFStrTest := 'e42666d73cee62653aecbce6b1bbf76134bf441f8fb04ac7be826bc2493cd537';
  lDataRow.PaddingByte              := 128;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

end;

procedure TestTHash_Haval256.TestDigestSize;
begin
  CheckEquals(32, FHash.DigestSize);
end;

procedure TestTHash_Haval256.TestGetMaxRounds;
begin
  CheckEquals(5, THash_Haval256(FHash).GetMaxRounds);
end;

procedure TestTHash_Haval256.TestGetMinRounds;
begin
  CheckEquals(5, THash_Haval256(FHash).GetMinRounds);
end;

procedure TestTHash_Haval256.TestIdentity;
begin
  CheckEquals($1A3C7B11, FHash.Identity);
end;

procedure TestTHash_Haval256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Haval256.TestSetRoundsMax;
var
  Hash : THash_Haval256;
begin
  Hash := FHash as THash_Haval256;

  Hash.Rounds := Hash.GetMinRounds;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds + 1;
  CheckEquals(5, Hash.Rounds);
end;

procedure TestTHash_Haval256.TestSetRoundsMin;
var
  Hash : THash_Haval256;
begin
  Hash := FHash as THash_Haval256;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(5, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds - 1;
  CheckEquals(5, Hash.Rounds);
end;

procedure TestTHash_Haval256.TestBlockSize;
begin
  CheckEquals(128, FHash.BlockSize);
end;

procedure TestTHash_Haval256.TestClassByName;
begin
  DoTestClassByName('THash_Haval256', THash_Haval256);
end;

procedure TestTHash_Tiger_3Rounds.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash        := THash_Tiger.Create;
  THash_Tiger(FHash).Rounds := 3;

  // Source until SourceEnd: http://www.cs.technion.ac.il/~biham/Reports/Tiger/
  //                         test-vectors-nessie-format.dat
  // Which is a subpage of the official Tiger website.
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3';
  lDataRow.ExpectedOutputUTFStrTest := '3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809';
  lDataRow.ExpectedOutputUTFStrTest := '5b548919bc71cca542473494052a8fab1b68c62be0f76985';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93';
  lDataRow.ExpectedOutputUTFStrTest := '70198191f5b6e901c884a5e61a8f16ea0ece41969289210e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd981f8cb78201a950dcf3048751e441c517fca1aa55a29f6';
  lDataRow.ExpectedOutputUTFStrTest := '5140a79cdf23f824ffb327896283d40e028987c3ae57aa56';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1714a472eee57d30040412bfcc55032a0b11602ff37beee9';
  lDataRow.ExpectedOutputUTFStrTest := '97fb5aed48239fd2487422f4289ca2774fcc39b1019b6c04';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e';
  lDataRow.ExpectedOutputUTFStrTest := '82b6b1126a60eaf0abdb326e31dc3a1559d86c4fe9747fe1';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');

//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := '8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc';
//  lDataRow.ExpectedOutputUTFStrTest := '82b6b1126a60eaf0abdb326e31dc3a1559d86c4fe9747fe1';
//  lDataRow.PaddingByte              := 1;
//  lDataRow.AddInputVector('A...Za...z0...9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd';
  lDataRow.ExpectedOutputUTFStrTest := 'e329bffcf56e3b751f3b143b31e91da68a9c2e89ef75532b';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('1234567890', 1, 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6db0e2729cbead93d715c6a7d36302e9b3cee0d2bc314b41';
  lDataRow.ExpectedOutputUTFStrTest := '0baf3bbd3bdf40a45b6ede3e4c3d644df75db942bc1f9570';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('a', 1, 1000000);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5d9ed00a030e638bdb753a6a24fb900e5a63b8e73e6c25b6';
  lDataRow.ExpectedOutputUTFStrTest := 'aabbcca084acecd0511d1f6232a17bfaefa441b2982e5548';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector(#0);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cdddcacfea7b70b485655ba3dc3f60dee4f6b8f861069e33';
  lDataRow.ExpectedOutputUTFStrTest := '10dd94b66ba6ae0498c9c7754844662e5d8b62e27d2c4d26';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector(#0, 24, 1);
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937';
  lDataRow.ExpectedOutputUTFStrTest := '54d1b0b346b9597343ff5a43d89a99c35f1066cff8fb9d52';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('Tiger');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f71c8583902afb879edfe610f82c0d4786a3a534504486b5';
  lDataRow.ExpectedOutputUTFStrTest := '7ff195ad4fcbd943fc12c42064f342ceb8dac80c21ba170f';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg');
  lDataRow.AddInputVector('h');
  lDataRow.AddInputVector('ijklmnopqrstuvwxyz0123456789+-');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '48ceeb6308b87d46e95d656112cdf18d97915f9765658957';
  lDataRow.ExpectedOutputUTFStrTest := 'e18bc4cd6b28b29012a93f02f03ce3db027b2c5a7a17e9a2';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8a866829040a410c729ad23f5ada711603b3cdd357e4c15e';
  lDataRow.ExpectedOutputUTFStrTest := 'ec87318e83e4e0a3a449430f2090ff8312d1977ef8fc0b19';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ce55a6afd591f5ebac547ff84f89227f9331dab0b611c889';
  lDataRow.ExpectedOutputUTFStrTest := '2a9c054f26080de941ac3a7853b0c9ff80f99b03510c1860';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '631abdd103eb9a3d245b6dfd4d77b257fc7439501d1568dd';
  lDataRow.ExpectedOutputUTFStrTest := '7fe631245eafd0a6fb2473c83a58a244ae60ea475880106b';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c54034e5b43eb8005848a7e0ae6aac76e4ff590ae715fd25';
  lDataRow.ExpectedOutputUTFStrTest := '9decaa95dac2e5d11617989563ad8c94d3236809e023ff59';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-', 2);

  // Self generated variants with different rounds
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194';
  lDataRow.ExpectedOutputUTFStrTest := '24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e2a0e5e38b778421cceafbfe9a37068b032093fd36be1635';
  lDataRow.ExpectedOutputUTFStrTest := 'ec116d1f4ef6f2144f63c70d2015bb3b0d59bda68733730d';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e765ebe4c351724a1b99f96f2d7e62c9aacbe64c63b5bca2';
  lDataRow.ExpectedOutputUTFStrTest := 'e765ebe4c351724a1b99f96f2d7e62c9aacbe64c63b5bca2';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '2746bc7889f68e8758257f2bc169be674d51608ce9dd65ed';
  lDataRow.ExpectedOutputUTFStrTest := 'd20a060f563803b54faa0922bd86a8719ec1df50754d678c';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6e30eae3390e2ca9335c9edfc90dc0f003eabad50918d9aa';
  lDataRow.ExpectedOutputUTFStrTest := '6e30eae3390e2ca9335c9edfc90dc0f003eabad50918d9aa';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 6;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bac32bc28a54f6d5ee26c85c7ae1ef61e5aad407cbf9a910';
  lDataRow.ExpectedOutputUTFStrTest := 'adf49bb1a1a141a9edc4bfd2f111d6316b71ff2f1d141679';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 6;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5337e218c7c12b1192fa10e5c63ed907af57bbd6d6146364';
  lDataRow.ExpectedOutputUTFStrTest := '5337e218c7c12b1192fa10e5c63ed907af57bbd6d6146364';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 7;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'df00ed0cfb9869be78a8cc6a58ba2c6dd8b012c1da3cc05e';
  lDataRow.ExpectedOutputUTFStrTest := '89b75dd95a5bf325c2ef7f3e9c9dab1b15f49ebfa567114a';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 7;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '822f272cb53c4186d4505dcea630813bc7e8fa9a92f573af';
  lDataRow.ExpectedOutputUTFStrTest := '822f272cb53c4186d4505dcea630813bc7e8fa9a92f573af';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4dce897c0aa41ed657ee3f124ece4ed22a433f53efba644d';
  lDataRow.ExpectedOutputUTFStrTest := 'ffe1544dfa924e8ece12417d10f738e98ab3dee135457bfd';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6cb2bc4ea50b592974add8aa516a30ba896fe7e1bc9c648b';
  lDataRow.ExpectedOutputUTFStrTest := '6cb2bc4ea50b592974add8aa516a30ba896fe7e1bc9c648b';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 9;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5401b91084bc1ebe1c1408d1989d3bbbec84e8e169920ded';
  lDataRow.ExpectedOutputUTFStrTest := '5a7a8551fd0a05e3d63d7fad19731be01a2a10cc52e47005';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 9;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ae19918f80fbbe6652da052a8156b2496482f0b0c5b939fb';
  lDataRow.ExpectedOutputUTFStrTest := 'ae19918f80fbbe6652da052a8156b2496482f0b0c5b939fb';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 10;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd4a80f966934a195dca058d40add105aab6be6500120df51';
  lDataRow.ExpectedOutputUTFStrTest := '288406055986df8cfa45e4383cfbe6c2dd0d8abc67c65328';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 10;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3ef6398161c991e08630cc02dabad92eb13ac606a8eb3d84';
  lDataRow.ExpectedOutputUTFStrTest := '3ef6398161c991e08630cc02dabad92eb13ac606a8eb3d84';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 11;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '75b4189ca752900826fe20ff9e353e71a09e5a737cca7d90';
  lDataRow.ExpectedOutputUTFStrTest := '7bda1f993777792cd0cda887fd6c2ee114f6c842e5d817b2';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 11;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd7ce83e7cc79f07337f320378232306f37f7842246555ccd';
  lDataRow.ExpectedOutputUTFStrTest := 'd7ce83e7cc79f07337f320378232306f37f7842246555ccd';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 12;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4ac77d8fca06eb2544a5c975d9d9c8ab9b878bd30ecdeba8';
  lDataRow.ExpectedOutputUTFStrTest := '5081fea9760d2ffa89b6e04a03992bb874b5cf87e2ffd76a';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 12;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aa49870819c7b4d567b4e9b5885f3fac4d65cf35cae6dda8';
  lDataRow.ExpectedOutputUTFStrTest := 'aa49870819c7b4d567b4e9b5885f3fac4d65cf35cae6dda8';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 13;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cd3f61c7c6272bc8e74e5e682d9d2564b7602fa0064d1135';
  lDataRow.ExpectedOutputUTFStrTest := '653329776b1ae6324d54ad32711cb52de6ba25317ee388dd';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 13;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '2b9aa826bef18c29206f6a07fd89d085cb4511f8fe45879c';
  lDataRow.ExpectedOutputUTFStrTest := '2b9aa826bef18c29206f6a07fd89d085cb4511f8fe45879c';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 14;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '554de6c8981aa6fcca22228898e4ae6f7c41cc7da3dcae2f';
  lDataRow.ExpectedOutputUTFStrTest := 'de9c211c6961a18ee78e03488b847d6715dc4dabd5b07307';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 14;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a0d3f6e1e4976828739e407845f06c7ca773ebdccf669c60';
  lDataRow.ExpectedOutputUTFStrTest := 'a0d3f6e1e4976828739e407845f06c7ca773ebdccf669c60';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 15;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '811b1fd5420f2e5a97dcb459fd381df617dacda430fc8508';
  lDataRow.ExpectedOutputUTFStrTest := 'a052c9bee462109367b096618b1cbf1f0ae1b01d82f85ba8';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 15;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6df4fdcd38811963c513247392df382f48f8e4849f7f3ad6';
  lDataRow.ExpectedOutputUTFStrTest := '6df4fdcd38811963c513247392df382f48f8e4849f7f3ad6';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 16;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6fb82ee580cfd5798c821884f4629f5799f8146c23f065c9';
  lDataRow.ExpectedOutputUTFStrTest := '8f0485953651d92d37fb25db1e443fe70583e43e7fcb216e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 16;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3590dee8092a56bddf46b909b5590c36558375089da934ec';
  lDataRow.ExpectedOutputUTFStrTest := '3590dee8092a56bddf46b909b5590c36558375089da934ec';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 17;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5d0f97e9c3acebf3311b3398547e4e725a53c77f809c911e';
  lDataRow.ExpectedOutputUTFStrTest := '6a3e2c5d326be12e0830c9e8861bee4f1d56f6e1120baa30';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 17;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '378017ad963f7ec7e6552a22e641f61ac7d343cae8c31514';
  lDataRow.ExpectedOutputUTFStrTest := '378017ad963f7ec7e6552a22e641f61ac7d343cae8c31514';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 18;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd239e4a37807dcc0a4692a67c1580d8c59f8f4a495e0c6ca';
  lDataRow.ExpectedOutputUTFStrTest := '961ec7a879f589043376a06abc33650f01078247be379549';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 18;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7f13cf1981b5d6604643de88f2b6c93fa9cb3ea121eb3961';
  lDataRow.ExpectedOutputUTFStrTest := '7f13cf1981b5d6604643de88f2b6c93fa9cb3ea121eb3961';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 19;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'fe86e525a5a233efb1178d9f1079acdb7bfd0b6c70c7f334';
  lDataRow.ExpectedOutputUTFStrTest := '3c65ee980663a446748671dd27871eada8dce99767efa464';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 19;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7b2e8ccd1cf6d82ee2d69fc934e74390c9b4589afe3cb793';
  lDataRow.ExpectedOutputUTFStrTest := '7b2e8ccd1cf6d82ee2d69fc934e74390c9b4589afe3cb793';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 20;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9eec3a05c9ed678507c35b296459953b1ce169e5244ebbcd';
  lDataRow.ExpectedOutputUTFStrTest := 'e9872f3ec69dc75b0d3ccf4787d2aa83be1adceeb9844093';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 20;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cb2b89a152fb416cc2943e770370216f24144608019b8fe7';
  lDataRow.ExpectedOutputUTFStrTest := 'cb2b89a152fb416cc2943e770370216f24144608019b8fe7';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 21;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6696a9c4d654f489fcf9a2a0b047df351dfd028028d63d20';
  lDataRow.ExpectedOutputUTFStrTest := '7f66bb24ac9763f39f1fb847febf52ab643a44f00b3c30c3';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 21;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd1df075117578d38710b1b98dd46e4bc952ffc415e975048';
  lDataRow.ExpectedOutputUTFStrTest := 'd1df075117578d38710b1b98dd46e4bc952ffc415e975048';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 22;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5e63ed6c5f96f1907ba452806d2e0a33084e53053c074aa1';
  lDataRow.ExpectedOutputUTFStrTest := 'f436db9086feccd6a5ebe01d2581c8065e1b721de69abdd7';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 22;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e0c437f0f012902417648e358c6f7a669d8a7b88d9f9e2fc';
  lDataRow.ExpectedOutputUTFStrTest := 'e0c437f0f012902417648e358c6f7a669d8a7b88d9f9e2fc';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 23;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '91b7092e164503fdbb2116662f622c5cccd94b4b5219f469';
  lDataRow.ExpectedOutputUTFStrTest := 'd52f0fbfc468304d2f988909a2d9a43fe64d2d1687dfc035';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 23;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '56336fd45156895ca48e40533133895a14562ce619283bfa';
  lDataRow.ExpectedOutputUTFStrTest := '56336fd45156895ca48e40533133895a14562ce619283bfa';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 24;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6b3c998afe86cdded92c057cba80d86953f4ac0a17ee8087';
  lDataRow.ExpectedOutputUTFStrTest := '61fe1d0ac706642d076d39b26476cef08fe6c7cf21ea651d';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 24;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'eae6f455e444669a9bb6f3a90f2c82108360e189fd203225';
  lDataRow.ExpectedOutputUTFStrTest := 'eae6f455e444669a9bb6f3a90f2c82108360e189fd203225';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 25;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f8f83cca45b25b0f24848c3f6d3d369c97db26b3194032d7';
  lDataRow.ExpectedOutputUTFStrTest := 'd5bb048fec29eb17e175a4cea767d8b236a1e46a2f91bf55';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 25;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c8692da2f95b4ab0fd998dc7bda63a3df6691c0ceab07a51';
  lDataRow.ExpectedOutputUTFStrTest := 'c8692da2f95b4ab0fd998dc7bda63a3df6691c0ceab07a51';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 26;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aaf3170253c30162910f4c1d0434722766fbcad5d2307a26';
  lDataRow.ExpectedOutputUTFStrTest := 'a1c24ee10c883666fb870b9a336db091d3379f736a8990ad';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 26;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ff43bbe31a569aa50c1926ae64afcdf0cdef0f4e98bbd2fc';
  lDataRow.ExpectedOutputUTFStrTest := 'ff43bbe31a569aa50c1926ae64afcdf0cdef0f4e98bbd2fc';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 27;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1a727cd9a0b13a838afc05c83f8826e0fd93383dd68030f3';
  lDataRow.ExpectedOutputUTFStrTest := 'e70606ca75db27708fe0ebde144715b9e6d25f05dcb84707';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 27;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4294ea0175517264aa3a6a7a33aa1a3814fa5f210a5dba39';
  lDataRow.ExpectedOutputUTFStrTest := '4294ea0175517264aa3a6a7a33aa1a3814fa5f210a5dba39';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 28;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f07d8af15589538b8524210dd605720edca25c2cf905f282';
  lDataRow.ExpectedOutputUTFStrTest := '65929f1afe61804fa542f8096c026e1273df6836db26fbde';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 28;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '73bab93d5e8e858c13851f3786d7d493e95a7eac1478bc2e';
  lDataRow.ExpectedOutputUTFStrTest := '73bab93d5e8e858c13851f3786d7d493e95a7eac1478bc2e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 29;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0643496a5a2dd9efa5d15352effd32298627ca33e90e870f';
  lDataRow.ExpectedOutputUTFStrTest := 'f7c634766d127281a1e2ef90a61d5bde3aab60abd7be4f8f';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 29;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1b688d42ea04d2ee32c1728c1f621a5cdfa2690dea1bf38a';
  lDataRow.ExpectedOutputUTFStrTest := '1b688d42ea04d2ee32c1728c1f621a5cdfa2690dea1bf38a';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 30;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '979bdfa0be86a13c4ee3a15ba0a38d3fe1c155fdf2205857';
  lDataRow.ExpectedOutputUTFStrTest := '962cf23bf3414f10f31233b19e2f9b3c5125af5bb37c144f';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 30;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ceea19a35a869e6ea59de7f4f66e28617640d1e5f55249ef';
  lDataRow.ExpectedOutputUTFStrTest := 'ceea19a35a869e6ea59de7f4f66e28617640d1e5f55249ef';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 31;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4bc7ad215c17c5da762a4436479892aeb5f902ec5a5e4d7c';
  lDataRow.ExpectedOutputUTFStrTest := 'fad8b8470dca2659b59e11dd388209f3cc1255a36012608f';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 31;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0c6ceaa3aa1841f0031963141877417a9c16f44c199dd81e';
  lDataRow.ExpectedOutputUTFStrTest := '0c6ceaa3aa1841f0031963141877417a9c16f44c199dd81e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 32;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5bbdf3a8e25ab4642dd047a59191134d972ff29d49cbfd07';
  lDataRow.ExpectedOutputUTFStrTest := '0c10a27c600377c13a932f0c8ea096b6f0b1d804d75847d3';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 32;
  lDataRow.AddInputVector('a');

  // Tests from former Tiger4Rounds test class which got merged in here after providing the
  // ability to specify the number of rounds in the test data
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194';
  lDataRow.ExpectedOutputUTFStrTest := '24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '538883c8fc5f28250299018e66bdf4fdb5ef7b65f2e91753';
  lDataRow.ExpectedOutputUTFStrTest := '8deb34e6f352e6b27c40be290f56f8db678022bbfb14913a';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aee020507279c0d2defcb767251cc0f824bbe38569d58ee4';
  lDataRow.ExpectedOutputUTFStrTest := '986161d6e753840ad58b8185244fe8ed76fcb282d51ec308';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('Tiger');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '439c699b3ca4f2d0cedc940fabca8941932a729a91950710';
  lDataRow.ExpectedOutputUTFStrTest := '8e776732af42a346f43809feb0eefdf5f7cc031347b1fb04';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg');
  lDataRow.AddInputVector('h');
  lDataRow.AddInputVector('ijklmnopqrstuvwxyz0123456789+-');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c5fe245ba8e9e3a056efd9f6cfa79cead8571a3c87fe62f1';
  lDataRow.ExpectedOutputUTFStrTest := '97bea30a65fea188ceff63018a806c71a251f3d57c81eac6';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '81100cdf2076b0e0392004f703449f41a37b840437b643ff';
  lDataRow.ExpectedOutputUTFStrTest := 'f637088a5036d9c5eb1b8f0624e63063a20cf6b2b646ae56';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a1e027aa525a38589ac97cfa325dc08417b3445ab3c27452';
  lDataRow.ExpectedOutputUTFStrTest := '15bdac6f9d89b892f55f111a7f74cbcad6f9ff16ded07717';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, '+
                          'proceedings of Fast Software Encryption 3, Cambridge.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f72ca9fa0db3332782d7b8ccac29575490b8100803212003';
  lDataRow.ExpectedOutputUTFStrTest := '7d8fa74429c8d0010df6015816638891d52e301ec1756b72';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, '+
                          'proceedings of Fast Software Encryption 3, Cambridge, 1996.');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '653b3075f1a85c6c74f1a9090b3c46239f29f0f92358e4e3';
  lDataRow.ExpectedOutputUTFStrTest := '21073aaf37e4a7bb0ccdaed0705a188f0c19c01f5c8bf7ce';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-', 2);
end;

procedure TestTHash_Tiger_3Rounds.TestDigestSize;
begin
  CheckEquals(24, FHash.DigestSize);
end;

procedure TestTHash_Tiger_3Rounds.TestGetMaxRounds;
begin
  CheckEquals(32, THash_Tiger(FHash).GetMaxRounds);
end;

procedure TestTHash_Tiger_3Rounds.TestGetMinRounds;
begin
  CheckEquals(3, THash_Tiger(FHash).GetMinRounds);
end;

procedure TestTHash_Tiger_3Rounds.TestIdentity;
begin
  CheckEquals($0E0D5F38, FHash.Identity);
end;

procedure TestTHash_Tiger_3Rounds.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Tiger_3Rounds.TestSetRoundsLowerLimit;
begin
  THash_Tiger(FHash).Rounds := 2;
  CheckEquals(3, THash_Tiger(FHash).Rounds);
end;

procedure TestTHash_Tiger_3Rounds.TestSetRoundsMax;
var
  Hash : THash_Tiger;
begin
  Hash := FHash as THash_Tiger;

  Hash.Rounds := Hash.GetMinRounds;
  CheckEquals(3, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds + 1;
  CheckEquals(32, Hash.Rounds);
end;

procedure TestTHash_Tiger_3Rounds.TestSetRoundsMin;
var
  Hash : THash_Tiger;
begin
  Hash := FHash as THash_Tiger;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(32, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds - 1;
  CheckEquals(3, Hash.Rounds);
end;

procedure TestTHash_Tiger_3Rounds.TestSetRoundsUpperLimit;
begin
  THash_Tiger(FHash).Rounds := 33;
  CheckEquals(32, THash_Tiger(FHash).Rounds);
end;

procedure TestTHash_Tiger_3Rounds.TestSetRounds;
begin
  THash_Tiger(FHash).Rounds := 5;
  CheckEquals(5, THash_Tiger(FHash).Rounds);
end;

procedure TestTHash_Tiger_3Rounds.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_Tiger_3Rounds.TestClassByName;
begin
  DoTestClassByName('THash_Tiger', THash_Tiger);
end;

procedure TestTHash_Panama.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Panama.Create;

  // An official source could not yet be found.

//  // Source until SourceEnd: http://radiogatun.noekeon.org/panama/
//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := '45d935220168bdcde830f65a6e46f3e91bb0bbd63d37a576718f40320c65079f';
//  lDataRow.ExpectedOutputUTFStrTest := 'aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b';
//  lDataRow.AddInputVector(TFormat_HEXL.Decode('002911b8f4046c0d18be467367847de24ae13b513d6c1b7e2cd6267d72ae641d'));
//
////  // jeweils mit dem benachbarten Byte getauscht: 11223344 -> 22114433
////  lDataRow.AddInputVector(TFormat_HEXL.Decode('2900b81104f40d6cbe1873468467e27de14a513b6c3d7e1bd62c7d26ae721d64'));
//
//  lDataRow := FTestData.AddRow;
//  lDataRow.ExpectedOutput           := '45d935220168bdcde830f65a6e46f3e91bb0bbd63d37a576718f40320c65079f';
//  lDataRow.ExpectedOutputUTFStrTest := 'aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b';
//  lDataRow.AddInputVector(TFormat_HEXL.Decode('69522bd85f903d8425558553c194e8051f7427d837edf3e4bc92253501eb3a6b'));
//  // SourceEnd




  // it was found out that this test vector for an empty string is the same as
  // in HashLib4Pascal, but that's no real proof.
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b';
  lDataRow.ExpectedOutputUTFStrTest := 'aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a2a70386b81fb918be17f00ff3e3b376a0462c4dc2eec7f2c63202c8874c037d';
  lDataRow.ExpectedOutputUTFStrTest := '123c6b5cfc252a1ba163ca3a9a89406f5ff2a93e9acdd34ebd1340d4955b65ea';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8f3c497bb2cc4ee1c09f025bd72effef2689e5ade788e5b633c31f7e18c53fec';
  lDataRow.ExpectedOutputUTFStrTest := 'fa49e779c987a87a602b65a86e3796976681c04715fdc4a2611e9282185b1c77';
  lDataRow.AddInputVector('0123456789abcdeffedcba987654321');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e7742dcf637952e28af6a4f55ab98f70285093162062a73a0baad08f579e83b3';
  lDataRow.ExpectedOutputUTFStrTest := 'c04b88a5dbbaadb4a3147fc381c6ad7e807a22ffee28a848542232f9f6fbbe22';
  lDataRow.AddInputVector('0123456789abcdeffedcba9876543210');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1';
  lDataRow.ExpectedOutputUTFStrTest := '1520099b14290b203224cd52c1ba43b372127d6a4abe146a2ce19fee5b55be4c';
  lDataRow.AddInputVector('The quick brown fox jumps over the lazy dog');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '63a7a70172f9f1896a8b636f50e7a3950a63fe7ecac9de0441d9f75b8377f664';
  lDataRow.ExpectedOutputUTFStrTest := 'df9ef3392dba9cfc3509310276c21047dbb5a9e9f46d850d0c4ffa452a1a761f';
  lDataRow.AddInputVector('0123456789abcdeffedcba9876543210', 1, 17);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f5f407b0987499b2af57b19fa63d92fc88a217b08a6928ab521c720a04be6825';
  lDataRow.ExpectedOutputUTFStrTest := '825aabccd6e012d24a453c7843bf99819a7ee921003d934b567d1dd2684f2bff';
  lDataRow.AddInputVector('0123456789abcdeffedcba987654321010123456789abcdeffedcba987654321010123456789abcdeffedcba98765432101', 1, 10);
  lDataRow.AddInputVector('0123456789abcdeffedcba98765432101', 3, 1);

end;

procedure TestTHash_Panama.TestDigestSize;
begin
  CheckEquals(32, FHash.DigestSize);
end;

procedure TestTHash_Panama.TestIdentity;
begin
  CheckEquals($323031D0, FHash.Identity);
end;

procedure TestTHash_Panama.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Panama.TestBlockSize;
begin
  CheckEquals(32, FHash.BlockSize);
end;

procedure TestTHash_Panama.TestClassByName;
begin
  DoTestClassByName('THash_Panama', THash_Panama);
end;

procedure TestTHash_Whirlpool0.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Whirlpool0.Create;

  // Source until SourceEnd: https://web.archive.org/web/20060621195406/http://
  //                           www.cosic.esat.kuleuven.ac.be/nessie/workshop/
  //                           submissions/whirlpool.zip
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b3e1ab6eaf640a34f784593f2074416accd3b8e62c620175fca' +
                                       '0997b1ba2347339aa0d79e754c308209ea36811dfa40c1c32f1' +
                                       'a2b9004725d987d3635165d3c8';
  lDataRow.ExpectedOutputUTFStrTest := 'b3e1ab6eaf640a34f784593f2074416accd3b8e62c620175fca' +
                                       '0997b1ba2347339aa0d79e754c308209ea36811dfa40c1c32f1' +
                                       'a2b9004725d987d3635165d3c8';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ee898fa681e89e1bba6764a5c07ced2f4a7bd1b8ec0637dd9ca' +
                                       'ca94d398db29baf6993b278231e2b7a3eecffe027928a4a4c9a' +
                                       'c6eb0de5f0fa58ede5949983d8';
  lDataRow.ExpectedOutputUTFStrTest := 'b31116c93f872f625cb09b270e0dc8e7ebc981a4fa671790c0d' +
                                       '5399aa0ada93ca24fc3fa8c510e81cd9070e0c8313afe5826b3' +
                                       '1887adeb7689988f9e95ad1ebf';
  lDataRow.AddInputVector(#$00);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8786611bb3601e913e9f9e0a77181fa6279b286f162e48d32c7' +
                                       '79ad2ca0168eae66bf50bb69fb889eaeabafd5613ff8d0aecba' +
                                       '52d8a1bcdd48935fa416a10cb8';
  lDataRow.ExpectedOutputUTFStrTest := '98fc1d5a206627ba22f14aedf9b7407ca76053d0f26297385e8' +
                                       '6b9ed105c993ab93f226b8e921a44de6e19b283f821ccd963df' +
                                       'b96594c1d84e7586ec68e20a92';
  lDataRow.AddInputVector(#$80);
  lDataRow.AddInputVector(#$00, 1, 63);
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f4b620445ae62431dbd6dbcec64d2a3031cd2f48df5e755f30b' +
                                       '3d069929ed4b4eda0ae65441bc86746021fb7f2167f84d67566' +
                                       'efaba003f0abb67a42a2ce5b13';
  lDataRow.ExpectedOutputUTFStrTest := 'a025014030d125c34d3629dde73304535597a7a06ce6b012686' +
                                       'cc064f9aba29fa943e8d07ce689aa2107f2f6162f71182b4ae1' +
                                       'ab9cfd6ddfb3eaa66a12cc3d01';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '54ee18b0bbd4dd38a211699f2829793156e5842df502a2a2599' +
                                       '5c6c541f28cc050ff57d4af772dee7cedcc4c34c3b8ec06446c' +
                                       '6657f2f36c2c06464399879b86';
  lDataRow.ExpectedOutputUTFStrTest := '8d41703489c5399ac0717eb23ec100a5a0ee247948b10f6fab1' +
                                       'be49fec61435a23bf5abc72c65ab30c1132d392cdf49d607e1c' +
                                       'd852cd8c97cf7fc56f50c1321c';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '29e158ba336ce7f930115178a6c86019f0f413adb283d8f0798' +
                                       'af06ca0a06d6d6f295a333b1c24bda2f429ac918a3748aef90f' +
                                       '7a2c8bfb084d5f979cf4e7b2b5';
  lDataRow.ExpectedOutputUTFStrTest := '5a8e0846029ec68f58ee2c38d2539a295a08a3495f63c98edf1' +
                                       '4787ed0be8a3cf7ccc941914b6096e09ba81ac16506718188bf' +
                                       '4b27b4719b44b9f7825946277f';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5ac9757e1407432daf348a972b8ad4a65c1123cf1f9b779c1ae' +
                                       '7ee2d540f30b3cefa8f98dca5fbb42084c5c2f161a7b40eb6b4' +
                                       'a1fc7f9aaab92a4bb6002edc5e';
  lDataRow.ExpectedOutputUTFStrTest := 'cca11e491b08a42a5c36df20f0c1b883b0f73948d3a1821e554' +
                                       '2f7230afc71ba0cc3dbdcb5da0418777cacee0df131a24a5c16' +
                                       '9a1d41e6cdf1e1d0a917f1952a';
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cae4175f09753de84974cfa968621092fe41ee9de913919c2b4' +
                                       '52e6cb424056721d640e563f628f29dd3bd0030837ae4ac14aa' +
                                       '17308505a92e5f7a92f112be75';
  lDataRow.ExpectedOutputUTFStrTest := 'f12fddbd9a619288f53f1c94920b24cddbd16a1bd07efebdba0' +
                                       'c9a93fd13c6f8aba44e2b11498a9e8679dc7a4ae50a928c4948' +
                                       '68758bf709c65443886213f789';
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e5965b4565b041a0d459610e5e48e944c4830cd16feba02d9d2' +
                                       '63e7da8de6a6b88966709bf28a5328d928312e7a172da4cff72' +
                                       'fe6de02277dae4b1dba49689a2';
  lDataRow.ExpectedOutputUTFStrTest := 'bf8878187b8fb4dfba01049f3de15714a7ecf48f0fc005cb41a' +
                                       '79ca4755ab6865409e84256953bca76a0592a5f23998f24b847' +
                                       '9d09678c5edc0cd4515ae35444';
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '76c8bc5f445140921ceaaed2afce4d0b0722fde3aea20145d9b' +
                                       '14a72d22799f2ebb88446b7b46f4646eb33fc7e6f153183b2fd' +
                                       '9e9a54557f41b10ab633b8b6e1';
  lDataRow.ExpectedOutputUTFStrTest := '3176130a3ffa3b8c9e904c4a3ca20912885613cdd5cad9c1f16' +
                                       '906e6e0521da5ba1456a93719a48bd51e22ece0b93a2c1ee533' +
                                       '95120946717e9695242fba7036';
  lDataRow.AddInputVector('abcdbcdecdefdefgefghfghighijhijk');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bb6cba9730d6c029c0c15fb7a2aa3597cf9442dad96a676c5ee' +
                                       '9a1d55f1d64d5e0d1ed0e71250ed960a1bd2e065642cfff1c97' +
                                       '6e061bab70d6c54d284eaaefb9';
  lDataRow.ExpectedOutputUTFStrTest := 'e5df9ba18452dd692fe434fd3427993fb1b33a9ac55a68161e1' +
                                       '17d1f6d01d7e87b78f907208e4432da35d2704d1d04ddc85051' +
                                       'ca892b2854c0908bd146789aa1';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bb6cba9730d6c029c0c15fb7a2aa3597cf9442dad96a676c5ee' +
                                       '9a1d55f1d64d5e0d1ed0e71250ed960a1bd2e065642cfff1c97' +
                                       '6e061bab70d6c54d284eaaefb9';
  lDataRow.ExpectedOutputUTFStrTest := 'e5df9ba18452dd692fe434fd3427993fb1b33a9ac55a68161e1' +
                                       '17d1f6d01d7e87b78f907208e4432da35d2704d1d04ddc85051' +
                                       'ca892b2854c0908bd146789aa1';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);

  // Test vector from EN Wikipedia article
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4f8f5cb531e3d49a61cf417cd133792ccfa501fd8da53ee368f' +
                                       'ed20e5fe0248c3a0b64f98a6533cee1da614c3a8ddec791ff05' +
                                       'fee6d971d57c1348320f4eb42d';
  lDataRow.ExpectedOutputUTFStrTest := '68a834ccecee9b794e8ad869d004cb0afae42f4b98da40dcd22' +
                                       '75ef295563ff15fc17ee9ceb0c153f19ab1b24ab959aa1acf08' +
                                       '5b8d6db01a25584ab32dce3356';
  lDataRow.AddInputVector('The quick brown fox jumps over the lazy dog');
end;

procedure TestTHash_Whirlpool0.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_Whirlpool0.TestDigestSize;
begin
  CheckEquals(64, FHash.DigestSize);
end;

procedure TestTHash_Whirlpool0.TestIdentity;
begin
  CheckEquals($D2619FF2, FHash.Identity);
end;

procedure TestTHash_Whirlpool0.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Whirlpool0.TestClassByName;
begin
  DoTestClassByName('THash_Whirlpool0', THash_Whirlpool0);
end;

{$IFDEF OLD_WHIRLPOOL_NAMES}
procedure TestTHash_Whirlpool.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash.Free;
  FHash := THash_Whirlpool.Create;
end;

procedure TestTHash_Whirlpool.TestIdentity;
begin
  CheckEquals($5CCB1E12, FHash.Identity);
end;

procedure TestTHash_Whirlpool.TestClassByName;
begin
  DoTestClassByName('THash_Whirlpool', THash_Whirlpool);
end;
{$ENDIF}

procedure TestTHash_WhirlpoolT.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_WhirlpoolT.Create;

  // Source until SourceEnd: https://en.wikipedia.org/wiki/Whirlpool_(hash_function)
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '470f0409abaa446e49667d4ebe12a14387cedbd10dd17b8243c' +
                                       'ad550a089dc0feea7aa40f6c2aaab71c6ebd076e43c7cfca0ad' +
                                       '32567897dcb5969861049a0f5a';
  lDataRow.ExpectedOutputUTFStrTest := '470f0409abaa446e49667d4ebe12a14387cedbd10dd17b8243c' +
                                       'ad550a089dc0feea7aa40f6c2aaab71c6ebd076e43c7cfca0ad' +
                                       '32567897dcb5969861049a0f5a';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '3ccf8252d8bbb258460d9aa999c06ee38e67cb546cffcf48e91' +
                                       'f700f6fc7c183ac8cc3d3096dd30a35b01f4620a1e3a20d79cd' +
                                       '5168544d9e1b7cdf49970e87f1';
  lDataRow.ExpectedOutputUTFStrTest := '9c7bb5e44e2721d1b442642719d7afffe2cad341a93ed823da0' +
                                       'fe84a63140af67467cfed7b268d45a77de6510b6e077f1ea0cd' +
                                       '69f19efdfd697c7089a3cc79dd';
  lDataRow.AddInputVector('The quick brown fox jumps over the lazy dog');
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ebaa1df2e97113be187eb0303c660f6e643e2c090ef2cda9a2e' +
                                       'a6dcf5002147d1d0e1e9d996e879cef9d26896630a5db3308d5' +
                                       'a0dc235b199c38923be2259e03';
  lDataRow.ExpectedOutputUTFStrTest := '5777fc1f8467a1c004cd9130439403ccdaa9fdc86092d9cffe3' +
                                       '39e6008612374d04c8fc0c724707feae6f7ceb1e030cabf652a' +
                                       '673da1849b02654af76eee24a7';
  lDataRow.AddInputVector(#$00);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a8583b83929bd46f0006e8401f87767ff0e23b96cd4cb2fe377' +
                                       '4901ee6eeed91f43ab569fb908122c53a264a35687b40a0590d' +
                                       '83e69fa82724380bae82a1caa0';
  lDataRow.ExpectedOutputUTFStrTest := '535497c6f54acf4a669eadae6f5005b149edbd36a6d32613e4d' +
                                       '81c5752948657d4c48f4dd851dd0cddccad88a5ce1ab32cb62a' +
                                       '692f3487d7490be2df6ca5c34c';
  lDataRow.AddInputVector(#$80);
  lDataRow.AddInputVector(#$00, 1, 63);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b290e0e7931025ed37043ad568f0036b40e6bff8f7455868780' +
                                       'f47ef7b5d693e62448029a9351cd85ac29cb0725e4cfeb996a9' +
                                       '2f2b8da8768483ac58ec0e492c';
  lDataRow.ExpectedOutputUTFStrTest := '528f3f670d4dfed05ff342f36d16b8a5a0d884da737dbc1b55c' +
                                       '2575362b5fbf9df895013bccc3a72dd7d78c157c52609b42633' +
                                       'a48affdd58297f44b3f40c5626';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8afc0527dcc0a19623860ef2369d0e25de8ebe2abaa40f598af' +
                                       'af6b07c002ed73e4fc0fc220fd4f54f74b5d6b07aa57764c3db' +
                                       'dcc2cdd919d89fa8155a34b841';
  lDataRow.ExpectedOutputUTFStrTest := '5e812e973466dde1b43dfcd752ec1828f53ecb0e330f6937311' +
                                       '159d6eded439994ccafa867a034266bc16ce73057343a01742d' +
                                       '8b13053aa1d4ce82f52f312fce';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '817eadf8efca5afbc11f71d0814e03a8d569c90f748c8603597' +
                                       'a7a0de3c8d55f528199010218249517b58b14bee52351560875' +
                                       '4b53a3cca35c0865ba5e361431';
  lDataRow.ExpectedOutputUTFStrTest := '5fb89db25c24f3c3d222302ead771d6c371c8fa0af40f62a422' +
                                       'cf092cf6af6bf0ab4c6707e25c34680bfdbf92973de78d37d9f' +
                                       'af2bed23dd9b27d53ed02ea473';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4afc2b07bddc8417635fcb43e695e16f45e116c226dd84339eb' +
                                       '95c2ccb39e7acbe1af8f7b1f3bd380077e71929498bc9682003' +
                                       '71f9299015434d1df109a0aa1d';
  lDataRow.ExpectedOutputUTFStrTest := '1925d2d0eaa3e76ed1cd7d95b0bdd03152f9d2193376f6348c0' +
                                       '64fc5115233f88a26610428bea98935464cce2078af9e81ca3f' +
                                       '31bdd5b5c5d5f3775c85569c1f';
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0f960ec9ab7d0c7e355a423d1ef4911a39797c836a71414276a' +
                                       'feb8fa475dba0c348547143162f3212edf1fb8d8c652a11a579' +
                                       'a399c2dbd837fe8608f5096131';
  lDataRow.ExpectedOutputUTFStrTest := 'c8176962d4e58e8e6174a3e3eecd1ab012345f3fa04ff06515b' +
                                       'b225bcdfa13ccbe5c53c357534aade7db3a46ff24c6c86bd5d3' +
                                       '465930c5d4ba0b734efcf8b43b';
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6ae43784c69d01c273bba40f8411495167909e0c1acc241473d' +
                                       '44e27bc8641e646535d38fce20604941988c387c201cff199c8' +
                                       'fa2afbedd036d66202892a7eee';
  lDataRow.ExpectedOutputUTFStrTest := '0fb6cadc695c10b27f8dc5a591e7856acc8edb22459060dfa28' +
                                       'd9f9532e1f7b2206b8b297f9d89f85570f73439592a45fd6475' +
                                       'd0a83923cead6eb443d3f69bb1';
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7da3991ff3d40e0beed44b89c83bed5b085cc390a2df47765c9' +
                                       '9ae2ddb0a1e2e094ef0e8b0cf7ba4733afd756ef8eef59b9181' +
                                       '29fe2efe0b00024d6c4e56dc45';
  lDataRow.ExpectedOutputUTFStrTest := '5586a2f7b714de8301412ff72d7bc8d4def56cece16ce4adc48' +
                                       'b3a6ef5b46ab17c979f8e1aedae3cbf4b74a4ea0e8b02e02032' +
                                       'a782094ff00fea088b78759ab9';
  lDataRow.AddInputVector('abcdbcdecdefdefgefghfghighijhijk');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0ee18ba7ca7ee091dace6285661eedf819a8fa17620f72aeffe' +
                                       '5aa62c462138b626aa09072a10fcbcfe7f7ff22db2f4d6d1f07' +
                                       '71856c4a7924f9b0e4044d9112';
  lDataRow.ExpectedOutputUTFStrTest := '6449537a67085f0ac0d80956d7d92d0cf0ec48cebde1728ad13' +
                                       'b88decd218a951f6b17303bfc552db14cff4607b4155eae9514' +
                                       '51d19010a7c43802a0495ccd68';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0ee18ba7ca7ee091dace6285661eedf819a8fa17620f72aeffe' +
                                       '5aa62c462138b626aa09072a10fcbcfe7f7ff22db2f4d6d1f07' +
                                       '71856c4a7924f9b0e4044d9112';
  lDataRow.ExpectedOutputUTFStrTest := '6449537a67085f0ac0d80956d7d92d0cf0ec48cebde1728ad13' +
                                       'b88decd218a951f6b17303bfc552db14cff4607b4155eae9514' +
                                       '51d19010a7c43802a0495ccd68';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
end;

procedure TestTHash_WhirlpoolT.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_WhirlpoolT.TestDigestSize;
begin
  CheckEquals(64, FHash.DigestSize);
end;

procedure TestTHash_WhirlpoolT.TestIdentity;
begin
  CheckEquals($98BE3AB3, FHash.Identity);
end;

procedure TestTHash_WhirlpoolT.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_WhirlpoolT.TestClassByName;
begin
  DoTestClassByName('THash_WhirlpoolT', THash_WhirlpoolT);
end;

{$IFDEF OLD_WHIRLPOOL_NAMES}
procedure TestTHash_Whirlpool1.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash.Free;
  FHash := THash_Whirlpool1.Create;
end;

procedure TestTHash_Whirlpool1.TestIdentity;
begin
  CheckEquals($A566AF64, FHash.Identity);
end;

procedure TestTHash_Whirlpool1.TestClassByName;
begin
  DoTestClassByName('THash_Whirlpool1', THash_Whirlpool1);
end;
{$ENDIF}

{$IFNDEF OLD_WHIRLPOOL_NAMES}
procedure TestTHash_Whirlpool1.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Whirlpool1.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4d9444c212955963d425a410176fccfb74161e6839692b4c11f' +
                                       'de2ed6eb559efe0560c39a7b61d5a8bcabd6817a3135af80f34' +
                                       '2a4942ccaae745abddfb6afed0';
  lDataRow.ExpectedOutputUTFStrTest := '8bdc9d4471d0dabd8812098b8cbdf5090beddb3d582917a61e1' +
                                       '76e3d22529d753fed9a37990ca18583855efbc4f26e88f62002' +
                                       'f67722eb05f74c7ea5e07013f5';
  lDataRow.AddInputVector(#$00);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '103e0055a9b090e11c8fddebba06c05ace8b64b896128f6eed3' +
                                       '071fcf3dc16946778e07223233fd180fc40ccdb8430a640e376' +
                                       '34271e655ca1674ebff507f8cb';
  lDataRow.ExpectedOutputUTFStrTest := 'caf45c33b5551249ce0fc6d59e778fcb46dc6b682c34a5382f2' +
                                       '8efaf3a9a605c9eae0feb081637322e7a56b369453e9ad36bd8' +
                                       '58537c103874b80aa4ab138368';
  lDataRow.AddInputVector(#$80);
  lDataRow.AddInputVector(#$00, 1, 63);

  // Source until SourceEnd: ISO-Testvectors from whirlpool.zip
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89af' +
                                       'ee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964' +
                                       'e59b63d93708b138cc42a66eb3';
  lDataRow.ExpectedOutputUTFStrTest := '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89af' +
                                       'ee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964' +
                                       'e59b63d93708b138cc42a66eb3';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c' +
                                       '45001d0087b42d11bc645413aeff63a42391a39145a591a9220' +
                                       '0d560195e53b478584fdae231a';

  lDataRow.ExpectedOutputUTFStrTest := '3f3a6a6d213b7d669e90f1309ff1dad4a6c8d0b0568109aa359' +
                                       '34a6586dcc5d1758b5ce644313310a1cf979c19c380b96af62b' +
                                       'dc82bd03bafd94f65d51d43188';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae' +
                                       '1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc' +
                                       '9d95d8b582d225292076d4eef5';
  lDataRow.ExpectedOutputUTFStrTest := '2c41adef13bbfd33743ca3aa26a2977852348de9b7e9b70a785' +
                                       'd34a661454403caa110de49f0641048acde14158a58a38b3a36' +
                                       '04a6a1096c64fdd880940191ae';
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f' +
                                       '5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed92' +
                                       '0052838f3362e86dbd37a8903e';
  lDataRow.ExpectedOutputUTFStrTest := '69da33ab06954bbb5dea0df780ce48f663e6333470f74b4f3df' +
                                       'bf5724087caeb816c4c661d3e9359740668ae07d2bf8432bfb1' +
                                       '07150e5540bd95681c4a744a3e';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442' +
                                       'ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f67' +
                                       '3e7207865d5d9819a3dba4eb3b';
  lDataRow.ExpectedOutputUTFStrTest := '970c5e7fbf85ab33e1faf78e0e2839955b4a0e401c954fdf778' +
                                       '673b625f35662f63fda7f77f5e6859493037d9d513e739c6643' +
                                       '98402f555f269cc04e0bc76528';
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'dc37e008cf9ee69bf11f00ed9aba26901dd7c28cdec066cc6af' +
                                       '42e40f82f3a1e08eba26629129d8fb7cb57211b9281a65517cc' +
                                       '879d7b962142c65f5a7af01467';
  lDataRow.ExpectedOutputUTFStrTest := 'a29d364116fb3398621689907e2baf7dba60a4b51ea3c9671b4' +
                                       'd2408761b3457a7b4ae1f2c6ef935f3f8cbe37578b9c39dac5b' +
                                       'acd1392b966a6943397db1048e';
  lDataRow.AddInputVector('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549' +
                                       'c4afadb6014294d5bd8df2a6c44e538cd047b2681a51a2c6048' +
                                       '1e88c5a20b2c2a80cf3a9a083b';
  lDataRow.ExpectedOutputUTFStrTest := '75ce932e300c665d5527f35d888f8a4fcde76cb693be179eac9' +
                                       '8a436542f1cf070c555bac1fef156a18106e3f8c09ddf3e7ef7' +
                                       'e6bfa5317ba97c7e8df9b7caf6';
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '2a987ea40f917061f5d6f0a0e4644f488a7a5a52deee656207c' +
                                       '562f988e95c6916bdc8031bc5be1b7b947639fe050b56939baa' +
                                       'a0adff9ae6745b7b181c3be3fd';
  lDataRow.ExpectedOutputUTFStrTest := '369e16f05a6866a72fc27b0a9f0582eb1e370a604b731712456' +
                                       '831ae19054dd189d276b32a0a664132146e9e07b8654cb9b3f4' +
                                       '312bc8b19a73ed572629b1718e';
  lDataRow.AddInputVector('abcdbcdecdefdefgefghfghighijhijk');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62de' +
                                       'ca0f1ccea4af51fc15490eddc47af32bb2b66c34ff9ad8c6008' +
                                       'ad677f77126953b226e4ed8b01';
  lDataRow.ExpectedOutputUTFStrTest := 'e1ddbc099459cad3d521ac1e8352a8946c3eeeacc9129299fdb' +
                                       'fc70c7d36de45ca602087d50adbee16c6f51157234673facfe5' +
                                       '3938c8735f3d4266d4b399424f';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 15625, 1);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62de' +
                                       'ca0f1ccea4af51fc15490eddc47af32bb2b66c34ff9ad8c6008' +
                                       'ad677f77126953b226e4ed8b01';
  lDataRow.ExpectedOutputUTFStrTest := 'e1ddbc099459cad3d521ac1e8352a8946c3eeeacc9129299fdb' +
                                       'fc70c7d36de45ca602087d50adbee16c6f51157234673facfe5' +
                                       '3938c8735f3d4266d4b399424f';
  lDataRow.AddInputVector('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1, 15625);
  // SourceEnd

  // Test vector from EN Wikipedia article
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4' +
                                       'fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31' +
                                       'f03ad62a5ef54e42ee82c3fb35';

  lDataRow.ExpectedOutputUTFStrTest := '54d79c3801365ff9e1c7c64796926ddd715e23a1ac48c3ab086' +
                                       '4eb2e29d681e6b0f628982c3167e1987053b5aacfa4e3f3dc53' +
                                       'af65923aa2e2beb2adc74b3591';
  lDataRow.AddInputVector('The quick brown fox jumps over the lazy dog');
end;

procedure TestTHash_Whirlpool1.TestBlockSize;
begin
  CheckEquals(64, FHash.BlockSize);
end;

procedure TestTHash_Whirlpool1.TestDigestSize;
begin
  CheckEquals(64, FHash.DigestSize);
end;

procedure TestTHash_Whirlpool1.TestIdentity;
begin
  CheckEquals($A566AF64, FHash.Identity);
end;

procedure TestTHash_Whirlpool1.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Whirlpool1.TestClassByName;
begin
  DoTestClassByName('THash_Whirlpool1', THash_Whirlpool1);
end;
{$ENDIF}

procedure TestTHash_Square.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Square.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '417b878eaf7d8ca82414e6e4c4a95149';
  lDataRow.ExpectedOutputUTFStrTest := '417b878eaf7d8ca82414e6e4c4a95149';
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '62148aad7927998c545c6f0e5feca9f0';
  lDataRow.ExpectedOutputUTFStrTest := 'bb806953f163a83880789c5793df24ff';
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '931b73d1a404f6f18880068056f6fc12';
  lDataRow.ExpectedOutputUTFStrTest := '636162bdda72d757efc056b108d82379';
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '2068598052889ea245b4906f621f398c';
  lDataRow.ExpectedOutputUTFStrTest := '3f1a4493b8bc057a279b9aa38917fb07';
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'fc356316c8a28b7dbfe0ff3fef52bf53';
  lDataRow.ExpectedOutputUTFStrTest := '7f63e6f9945e40a16befe6c08347a65f';
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b8654c7c554f18541bb28794a17f0c09';
  lDataRow.ExpectedOutputUTFStrTest := '07035852e0f0c5b8282f11bd83a3e60f';
  lDataRow.AddInputVector('A');
  lDataRow.AddInputVector('BCDEFGHIJKLMNOPQRS');
  lDataRow.AddInputVector('TUVWXYZabcdefghijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '0c004c5b7066610e2a2dd2eecaee3186';
  lDataRow.ExpectedOutputUTFStrTest := '1b1a00a69f0f19e887574b1f6a792412';
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c3ba10de37cdec5e99def41475f1df5d';
  lDataRow.ExpectedOutputUTFStrTest := 'fd99b6eda660c726d0a4e47e13018cfb';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '058a1da3a62f3e6a8ba9135373a089ca';
  lDataRow.ExpectedOutputUTFStrTest := '9148d4fc4379235a5a065ef88a51cb1d';
  lDataRow.AddInputVector('This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.');

end;

procedure TestTHash_Square.TestDigestSize;
begin
  CheckEquals(16, FHash.DigestSize);
end;

procedure TestTHash_Square.TestIdentity;
begin
  CheckEquals($996BCEE5, FHash.Identity);
end;

procedure TestTHash_Square.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Square.TestBlockSize;
begin
  CheckEquals(16, FHash.BlockSize);
end;

procedure TestTHash_Square.TestClassByName;
begin
  DoTestClassByName('THash_Square', THash_Square);
end;

procedure TestTHash_Snefru128.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Snefru128.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8617f366566a011837f4fb4ba5bedea2';
  lDataRow.ExpectedOutputUTFStrTest := '8617f366566a011837f4fb4ba5bedea2';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('');

  // Source until SourceEnd: http://ftp.vim.org/security/coast/crypto/snefru/snefru.c
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd9fcb3171c097fbba8c8f12aa0906bad';
  lDataRow.ExpectedOutputUTFStrTest := 'ab3974fcd9f1caa6a2ae226c2974fb0c';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector(#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '44ec420ce99c1f62feb66c53c24ae453';
  lDataRow.ExpectedOutputUTFStrTest := '39deead469aec32c2ce66aebb7ec3eec';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('1'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7182051aa852ef6fba4b6c9c9b79b317';
  lDataRow.ExpectedOutputUTFStrTest := '3e34c975f5308c71523b3fc39a3692e6';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('12'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bc3a50af82bf56d6a64732bc7b050a93';
  lDataRow.ExpectedOutputUTFStrTest := 'e71945a2fcd0f0d992b5d24b6a49547f';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('123'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c5b8a04985a8eadfb4331a8988752b77';
  lDataRow.ExpectedOutputUTFStrTest := 'ad32e4eb4cbf5c482194596f28902240';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('1234'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd559a2b62f6f44111324f85208723707';
  lDataRow.ExpectedOutputUTFStrTest := 'a8b025b7cddd0555b9241dcf16fbd798';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('12345'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6cfb5e8f1da02bd167b01e4816686c30';
  lDataRow.ExpectedOutputUTFStrTest := '73b7248a11bbb8425863eec60e5d8a43';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('123456'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '29aa48325f275a8a7a01ba1543c54ba5';
  lDataRow.ExpectedOutputUTFStrTest := 'd5c92cb71197ee91fd4f347b8fbac655';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('1234567'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'be862a6b68b7df887ebe00319cbc4a47';
  lDataRow.ExpectedOutputUTFStrTest := '8b7b3408b144335774eb6c276ded6e00';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('12345678'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6103721ccd8ad565d68e90b0f8906163';
  lDataRow.ExpectedOutputUTFStrTest := '1a624aa607071a337558911531a0dde6';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('123456789'#$0A);
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '553d0648928299a0f22a275a02c83b10';
  lDataRow.ExpectedOutputUTFStrTest := '94f3567822b3fe5299c0e109dff4fa70';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7840148a66b91c219c36f127a0929606';
  lDataRow.ExpectedOutputUTFStrTest := '9823d5f81402ac45b790633af492097b';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd9204ed80bb8430c0b9c244fe485814a';
  lDataRow.ExpectedOutputUTFStrTest := '9a92c0b5e89851f4a5faaa441c250931';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('1234567890', 8);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'dd0d1ab288c3c36671044f41c5077ad6';
  lDataRow.ExpectedOutputUTFStrTest := '150c6230252f8497c64f6ccff97928f8';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('Test message for buffer workflow test(47 bytes)');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e7054f05bd72d7e86a052153a17c741d';
  lDataRow.ExpectedOutputUTFStrTest := '3ab419c9af627272b2e2cdafed2b7150';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('Test message for buffer workflow test(48 bytes).');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9b34204833422df13c83e10a0c6d080a';
  lDataRow.ExpectedOutputUTFStrTest := '906816013ee57f3d2ae1562b9590d82f';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('Test message for buffer workflow test(49 bytes)..');

  // Self generated variants with different rounds
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b67224738c99d0ef185f2e971eb762ae';
  lDataRow.ExpectedOutputUTFStrTest := 'b67224738c99d0ef185f2e971eb762ae';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 2;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '539c64ded2a44b97ed4f0711004edaad';
  lDataRow.ExpectedOutputUTFStrTest := 'fc6f9f482b0d0723ffed58fc82d90ecc';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 2;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9aeac4d3d3e296ad4e566c6e2811b85a';
  lDataRow.ExpectedOutputUTFStrTest := '9aeac4d3d3e296ad4e566c6e2811b85a';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7e1f7a00983fa324168f780929a0c4c7';
  lDataRow.ExpectedOutputUTFStrTest := 'cc882f105b7e399c2a632c0501a8af05';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5148516ae7fc7e89ad8e0b0b8d76ac78';
  lDataRow.ExpectedOutputUTFStrTest := '5148516ae7fc7e89ad8e0b0b8d76ac78';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5e805ed80354e9691a1b2efde15e912f';
  lDataRow.ExpectedOutputUTFStrTest := '705ec2a3cfe525d6ffc11c9954515e86';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5ba0047e7d6cbdfbff10fad5490c6d38';
  lDataRow.ExpectedOutputUTFStrTest := '5ba0047e7d6cbdfbff10fad5490c6d38';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b7eab52063997cf0f9af9b48f40ef4de';
  lDataRow.ExpectedOutputUTFStrTest := '2e4841da4f75eb194700b917fd47dc7a';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '121baa1ecd1a1142c12d26a1bb775b65';
  lDataRow.ExpectedOutputUTFStrTest := '121baa1ecd1a1142c12d26a1bb775b65';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 6;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '27d8e5aa9b80f028e7584b4288c981d5';
  lDataRow.ExpectedOutputUTFStrTest := '5988c4849fb285c4c47ef5d9202b0f8f';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 6;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '07c8fa1b2d6fd256721f5d9a32ae5d65';
  lDataRow.ExpectedOutputUTFStrTest := '07c8fa1b2d6fd256721f5d9a32ae5d65';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 7;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '527a095ba679879a79d443a07d3772b9';
  lDataRow.ExpectedOutputUTFStrTest := 'b2792fb5beb5060e96fdebd5e564e5be';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 7;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bf5ce540ae51bc50399f96746c5a15bd';
  lDataRow.ExpectedOutputUTFStrTest := 'ac49ea6c1b5f4191c2fdfbab7e87c141';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('a');
end;

procedure TestTHash_Snefru128.TestDigestSize;
begin
  CheckEquals(16, FHash.DigestSize);
end;

procedure TestTHash_Snefru128.TestGetMaxRounds;
begin
  CheckEquals(8, THash_Snefru128(FHash).GetMaxRounds);
end;

procedure TestTHash_Snefru128.TestGetMinRounds;
begin
  CheckEquals(2, THash_Snefru128(FHash).GetMinRounds);
end;

procedure TestTHash_Snefru128.TestIdentity;
begin
  CheckEquals($E3374275, FHash.Identity);
end;

procedure TestTHash_Snefru128.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Snefru128.TestSetRoundsMax;
var
  Hash : THash_Snefru128;
begin
  Hash := FHash as THash_Snefru128;

  Hash.Rounds := Hash.GetMinRounds;
  CheckEquals(2, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(8, Hash.Rounds);

  Hash.Rounds := 3;
  CheckEquals(3, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds + 1;
  CheckEquals(8, Hash.Rounds);
end;

procedure TestTHash_Snefru128.TestSetRoundsMin;
var
  Hash : THash_Snefru128;
begin
  Hash := FHash as THash_Snefru128;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(8, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds;
  CheckEquals(2, Hash.Rounds);

  Hash.Rounds := 3;
  CheckEquals(3, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds - 1;
  CheckEquals(8, Hash.Rounds);
end;

procedure TestTHash_Snefru128.TestBlockSize;
begin
  CheckEquals(48, FHash.BlockSize);
end;

procedure TestTHash_Snefru128.TestClassByName;
begin
  DoTestClassByName('THash_Snefru128', THash_Snefru128);
end;

procedure TestTHash_Snefru256.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Snefru256.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881';
  lDataRow.ExpectedOutputUTFStrTest := '8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('');

  // Source until SourceEnd: http://ftp.vim.org/security/coast/crypto/snefru/snefru.c
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '2e02687f0d45d5b9b50cb68c3f33e6843d618a1aca2d06893d3eb4e3026b5732';
  lDataRow.ExpectedOutputUTFStrTest := 'ea81f0d664c9f14b5af04103212ea129001da9c3c421b6e340bdb9ece6c90244';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector(#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'bfea4a05a2a2ef15c736d114598a20b9d9bd4d66b661e6b05ecf6a7737bdc58c';
  lDataRow.ExpectedOutputUTFStrTest := 'd26379b028a12a8f8f1b04396a1907ff61e70bf9184c32ebfb254c4e15138762';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('1'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ac677d69761ade3f189c7aef106d5fe7392d324e19cc76d5db4a2c05f2cc2cc5';
  lDataRow.ExpectedOutputUTFStrTest := 'f3530df84977152b8a38867acf14c9a46cfae162f9543c986a500cf32d5a7359';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('12'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '061c76aa1db4a22c0e42945e26c48499b5400162e08c640be05d3c007c44793d';
  lDataRow.ExpectedOutputUTFStrTest := '25987aee97eeee4d4e3914e8245ecdfe69e45cbe0e728175cb4411e046091fd4';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('123'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1e87fe1d9c927e9e24be85e3cc73359873541640a6261793ce5a974953113f5e';
  lDataRow.ExpectedOutputUTFStrTest := 'b76fbfabada71bf38decdd3b4e19ec39292a496dd23c29755c4a96caf77d4b13';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('1234'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '1b59927d85a9349a87796620fe2ff401a06a7ba48794498ebab978efc3a68912';
  lDataRow.ExpectedOutputUTFStrTest := '6598676a170cf7075cee8b54da5844a824c0e1cb9830773ba9728ca2c65f7fe5';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('12345'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '28e9d9bc35032b68faeda88101ecb2524317e9da111b0e3e7094107212d9cf72';
  lDataRow.ExpectedOutputUTFStrTest := '062cc2b932500825575447e87a9416f38d561b0b3111b36011a9e6ef773cf54b';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('123456'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'f7fff4ee74fd1b8d6b3267f84e47e007f029d13b8af7e37e34d13b469b8f248f';
  lDataRow.ExpectedOutputUTFStrTest := '45b05d5126783c33b68f9a813cb3010f84cc9c1d6b133391a88ae61b43c89cc5';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('1234567'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'ee7d64b0102b2205e98926613b200185559d08be6ad787da717c968744e11af3';
  lDataRow.ExpectedOutputUTFStrTest := '9e614b25cd9d6b260c2fdeb59b1d6de8e8329157aa581a9f63424b4c012bd0df';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('12345678'#$0A);

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4ca72639e40e9ab9c0c3f523c4449b3911632d374c124d7702192ec2e4e0b7a3';
  lDataRow.ExpectedOutputUTFStrTest := '7dde03a5c268df01f5cdc408dc1807a677954e6aaf9ad0d6235809b758ef7691';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('123456789'#$0A);
  // SourceEnd

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b';
  lDataRow.ExpectedOutputUTFStrTest := '116509bcc4ec01f1b14d7769241cdb2438073bf9ed2031b11efb52913c0a635c';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9304bb2f876d9c4f54546cf7ec59e0a006bead745f08c642f25a7c808e0bf86e';
  lDataRow.ExpectedOutputUTFStrTest := '78040669e962b45dd079ad1d98c5a222356c48ae83c531e192a32c34affbf6ae';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd5fce38a152a2d9b83ab44c29306ee45ab0aed0e38c957ec431dab6ed6bb71b8';
  lDataRow.ExpectedOutputUTFStrTest := '5fa0a6e55b18b8db6f17280bf1312f1b9651664a849feecb34fd792c392f0ae6';
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('1234567890', 8);

  // Self generated variants with different rounds
  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b67224738c99d0ef185f2e971eb762ae6d2b456f58734709230b74a2e04bdcee';
  lDataRow.ExpectedOutputUTFStrTest := 'b67224738c99d0ef185f2e971eb762ae6d2b456f58734709230b74a2e04bdcee';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 2;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'fe211b27f86682ef3a618af1074e3944e4a2a1aac874e36ac3c345e72942baf9';
  lDataRow.ExpectedOutputUTFStrTest := '616cf9587293327c5b8ba8261f59042762b9232d6cb723915b2e4e3b685e6544';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 2;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '9aeac4d3d3e296ad4e566c6e2811b85a5ba12c9d81b16f07edcaf69222911d4c';
  lDataRow.ExpectedOutputUTFStrTest := '9aeac4d3d3e296ad4e566c6e2811b85a5ba12c9d81b16f07edcaf69222911d4c';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'acff01a0c465ca381e33414e7d5c62128798a1782dac754e4cfebaa4e92d62ad';
  lDataRow.ExpectedOutputUTFStrTest := '6d852e82108123b87836db95f7037afb966041e13139ea721928527d7b5b44e3';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 3;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5148516ae7fc7e89ad8e0b0b8d76ac782498615818fb8eeb08cbab9f07c82a73';
  lDataRow.ExpectedOutputUTFStrTest := '5148516ae7fc7e89ad8e0b0b8d76ac782498615818fb8eeb08cbab9f07c82a73';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '96240e570bb4677118588156980c1122131c6592aca33a141293348669c9999d';
  lDataRow.ExpectedOutputUTFStrTest := '3e08ee766c72a975bb4a036a3302fe84f485794fcecd8703eecea844cf1cd424';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 4;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5ba0047e7d6cbdfbff10fad5490c6d380308a437fbddbb353b1b87083390a21d';
  lDataRow.ExpectedOutputUTFStrTest := '5ba0047e7d6cbdfbff10fad5490c6d380308a437fbddbb353b1b87083390a21d';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '00c41213cdc4d6339e3a986448d7a67e8d5fa66bcd1b08371eda8a31d3dc45f4';
  lDataRow.ExpectedOutputUTFStrTest := '0f1dec19775f20a413378a3f75806d28c8ddfae75bf46b5497350322d0b7751f';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 5;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '121baa1ecd1a1142c12d26a1bb775b658a8e9ac1295d6a6eaa7f2b2cb8d45128';
  lDataRow.ExpectedOutputUTFStrTest := '121baa1ecd1a1142c12d26a1bb775b658a8e9ac1295d6a6eaa7f2b2cb8d45128';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 6;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b129dc99917c4ac28ef49179e33426db95dcb7e9285989c420382bae7c2a7145';
  lDataRow.ExpectedOutputUTFStrTest := '7bc3f5504d4eae0c87253c5320c38f4f0d8a7e2e37b9641ca5fb3906863e98a7';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 6;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '07c8fa1b2d6fd256721f5d9a32ae5d6582890b28f4f5b5e2d7866d1917222a18';
  lDataRow.ExpectedOutputUTFStrTest := '07c8fa1b2d6fd256721f5d9a32ae5d6582890b28f4f5b5e2d7866d1917222a18';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 7;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'db4092e587f30ec659ecd8a71479917e5811f161c9daa49158505fa20c26d51d';
  lDataRow.ExpectedOutputUTFStrTest := '428f156a2e89ab53f14597eeea9fc9ed08bfb5c7472776da216271058f11522e';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 7;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '45161589ac317be0ceba70db2573ddda6e668a31984b39bf65e4b664b584c63d';
  lDataRow.ExpectedOutputUTFStrTest := 'fa5f1bed326200b7e25f2d2d8e55f67f4214aa37b3905a613176b2f0f086491d';
  lDataRow.PaddingByte              := 1;
  lDataRow.Rounds                   := 8;
  lDataRow.AddInputVector('a');
end;

procedure TestTHash_Snefru256.TestDigestSize;
begin
  CheckEquals(32, FHash.DigestSize);
end;

procedure TestTHash_Snefru256.TestGetMaxRounds;
begin
  CheckEquals(8, THash_Snefru256(FHash).GetMaxRounds);
end;

procedure TestTHash_Snefru256.TestGetMinRounds;
begin
  CheckEquals(2, THash_Snefru256(FHash).GetMinRounds);
end;

procedure TestTHash_Snefru256.TestIdentity;
begin
  CheckEquals($498847EC, FHash.Identity);
end;

procedure TestTHash_Snefru256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Snefru256.TestSetRoundsMax;
var
  Hash : THash_Snefru256;
begin
  Hash := FHash as THash_Snefru256;

  Hash.Rounds := Hash.GetMinRounds;
  CheckEquals(2, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(8, Hash.Rounds);

  Hash.Rounds := 3;
  CheckEquals(3, Hash.Rounds);

  Hash.Rounds := Hash.GetMaxRounds + 1;
  CheckEquals(8, Hash.Rounds);
end;

procedure TestTHash_Snefru256.TestSetRoundsMin;
var
  Hash : THash_Snefru256;
begin
  Hash := FHash as THash_Snefru256;

  Hash.Rounds := Hash.GetMaxRounds;
  CheckEquals(8, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds;
  CheckEquals(2, Hash.Rounds);

  Hash.Rounds := 3;
  CheckEquals(3, Hash.Rounds);

  Hash.Rounds := Hash.GetMinRounds - 1;
  CheckEquals(8, Hash.Rounds);
end;

procedure TestTHash_Snefru256.TestBlockSize;
begin
  CheckEquals(32, FHash.BlockSize);
end;

procedure TestTHash_Snefru256.TestClassByName;
begin
  DoTestClassByName('THash_Snefru256', THash_Snefru256);
end;

procedure TestTHash_Sapphire.ConfigHashClass(aHashClass: TDECHash; aIdxTestData: Integer);
begin
  inherited;
  THash_Sapphire(FHash).RequestedDigestSize := FTestData[aIdxTestData].RequiredDigestSize;
end;

procedure TestTHash_Sapphire.SetUp;
var lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_Sapphire.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c1e0df6ce706a32fb7b25b7ac55f436a';
  lDataRow.ExpectedOutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436a';
  lDataRow.RequiredDigestSize       := 16;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4acf17d911781571f053ce82e2f70cce';
  lDataRow.ExpectedOutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822';
  lDataRow.RequiredDigestSize       := 16;
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe5';
  lDataRow.ExpectedOutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe5';
  lDataRow.RequiredDigestSize       := 20;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4acf17d911781571f053ce82e2f70cce5470f410';
  lDataRow.ExpectedOutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25c';
  lDataRow.RequiredDigestSize       := 20;
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54';
  lDataRow.ExpectedOutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54';
  lDataRow.RequiredDigestSize       := 24;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a6';
  lDataRow.ExpectedOutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8d';
  lDataRow.RequiredDigestSize       := 24;
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb';
  lDataRow.ExpectedOutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb';
  lDataRow.RequiredDigestSize       := 28;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a699063814';
  lDataRow.ExpectedOutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8ddc81aad5';
  lDataRow.RequiredDigestSize       := 28;
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f';
  lDataRow.ExpectedOutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f';
  lDataRow.RequiredDigestSize       := 32;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a699063814b6df1f32';
  lDataRow.ExpectedOutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8ddc81aad5cba2e6d3';
  lDataRow.RequiredDigestSize       := 32;
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f34606520';
  lDataRow.ExpectedOutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f34606520';
  lDataRow.RequiredDigestSize       := 36;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a699063814b6df1f327c766773';
  lDataRow.ExpectedOutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8ddc81aad5cba2e6d37eb8dbc4';
  lDataRow.RequiredDigestSize       := 36;
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f34606520fa7a5ad7';
  lDataRow.ExpectedOutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f34606520fa7a5ad7';
  lDataRow.RequiredDigestSize       := 40;
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8b3763c9e423995743a702a37cc4a82c9771c7ac04fe44990d2cf64a311715406a59cf62b0b4edc9';
  lDataRow.ExpectedOutputUTFStrTest := 'a947fdf3a224bcd948c426cec358e84c8468ff42af47dd558979953ee426213ac2f415b0c3c9d476';
  lDataRow.RequiredDigestSize       := 40;
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a699063814b6df1f327c766773fc59830b';
  lDataRow.ExpectedOutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8ddc81aad5cba2e6d37eb8dbc44c70af77';
  lDataRow.RequiredDigestSize       := 40;
  lDataRow.AddInputVector('ab');
  lDataRow.AddInputVector('c');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e0affc0f16c9303c9938dbc9b1e6be3a3dcb75a2879ef8227fdd42595980793c94e7d3e33ce0a20a';
  lDataRow.ExpectedOutputUTFStrTest := 'f8ddc0058786d1094b005901927e6743ec8a46ba69a8c0e3821086510dfc338ec839fb729a733c3b';
  lDataRow.RequiredDigestSize       := 40;
  lDataRow.AddInputVector('message digest');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '23b86cf1a67c6870b90e594be9b4eda4c3862036edf1efb03c86863c274585cf5837429f1ff6f4b0';
  lDataRow.ExpectedOutputUTFStrTest := '14d2bc67c1d0ec0afaadff77f03fe563156d416b232eb2f995a038cb5de6a19dcbc3e773decca6ab';
  lDataRow.RequiredDigestSize       := 40;
  lDataRow.AddInputVector('abcdefghijklm');
  lDataRow.AddInputVector('nopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '341530ae3c1f715197847eddd38b4f58cc9a13c3e65f890772c9c561b103d2bf41340dff2af0335f';
  lDataRow.ExpectedOutputUTFStrTest := 'da208c7d3cbb8280f0f9be7b88b6cc54ea24eb9dd900071b15b83cfb6abe68dce87c27f7ce1097ff';
  lDataRow.RequiredDigestSize       := 40;
  lDataRow.AddInputVector('A');
  lDataRow.AddInputVector('BCDEFGHIJKLMNOPQRS');
  lDataRow.AddInputVector('TUVWXYZabcdefghijklmnopqrstuvwxyz012345678');
  lDataRow.AddInputVector('9');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5bb5a1bd1ad4974042aa74992489fbdec857212a29cedc67b1fc79ddc9f139c3f52044be4e6f8588';
  lDataRow.ExpectedOutputUTFStrTest := '87b0a006a73261011c4df04dc164216cfe566e54f92f161fec529c3cc956929955b1dc1cbe0215fa';
  lDataRow.RequiredDigestSize       := 40;
  lDataRow.AddInputVector('1234567890', 8);

end;

procedure TestTHash_Sapphire.TestDigestSize;
begin
  CheckEquals(64, FHash.DigestSize);
end;

procedure TestTHash_Sapphire.TestIdentity;
begin
  CheckEquals($8442C643, FHash.Identity);
end;

procedure TestTHash_Sapphire.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_Sapphire.TestBlockSize;
begin
  CheckEquals(1, FHash.BlockSize);
end;

procedure TestTHash_Sapphire.TestClassByName;
begin
  DoTestClassByName('THash_Sapphire', THash_Sapphire);
end;

{ THash_TestBase }

procedure THash_TestBase.ConfigHashClass(HashClass: TDECHash; IdxTestData: Integer);
begin
  HashClass.PaddingByte := FTestData[IdxTestData].PaddingByte;
  SetPropertyValue(HashClass, 'Rounds', FTestData[IdxTestData].Rounds.ToString);
end;

function THash_TestBase.SetPropertyValue(aInstance: TObject; const PropertyName, Value: string):Boolean;
var
  Ctx: TRttiContext;
  Prop: TRttiProperty;
begin
  Prop := Ctx.GetType(aInstance.ClassType).GetProperty(PropertyName);
  if (Prop <> nil) and (Prop.Visibility in [mvPublic, mvPublished]) then
  begin
    case Prop.PropertyType.TypeKind of
      tkInteger, tkInt64  : Prop.SetValue(aInstance, Value.ToInteger);
      tkFloat             : Prop.SetValue(aInstance, Value.ToDouble);
      tkString, tkUString : Prop.SetValue(aInstance, Value);
      else
      begin
        Result := false;
        exit;
      end;
//      TTypeKind.
    end;

    Result := true;
  end
  else
    Result := false;
end;

procedure THash_TestBase.DoTest52(HashClass: TDECHash);
var
  i                   : Integer;
  Buf                 : TBytes;
  BufLen              : Integer; // Buffer length in whole bytes, may differ from
                                 // input vector legtht at least for SHA3 test
  InputDataVectors    : ITestDataInputVectorList;
  IdxVector           : Integer;
  IdxCount            : Integer;
  HashResult          : TBytes;
  HashResultRawString : RawByteString;
  HashResultString    : string;
  ResultExpected      : string;
  ResultCalculated    : string;
begin
  for i := 0 to FTestData.Count-1 do
  begin
    InputDataVectors := FTestData[i].InputDataVectors;

    HashClass.Init;
    ConfigHashClass(HashClass, i);

    for IdxVector := 0 to InputDataVectors.Count-1 do
    begin
      Buf := BytesOf(RawByteString(InputDataVectors[IdxVector].Data));
      BufLen := Length(Buf);

      // Last part of the test data are bits (relevant for SHA3) and this old
      // style test variant does not know how to handle this.
      if FTestData[i].FinalByteBitLength > 0 then
        Break;

      if length(Buf) > 0 then
      begin
        for IdxCount := 1 to InputDataVectors[IdxVector].RepeatCount do
          HashClass.Calc(Buf[0], BufLen);
      end
      else
      begin
        for IdxCount := 1 to InputDataVectors[IdxVector].RepeatCount do
          HashClass.Calc(Buf, BufLen);
      end;
    end;

      // Last part of the test data are bits (relevant for SHA3) and this old
      // style test variant does not know how to handle this.
    if FTestData[i].FinalByteBitLength > 0 then
      Continue;

    HashClass.Done;
    HashResult          := HashClass.DigestAsBytes;
    HashResultRawString := HashClass.DigestAsRawByteString;
    HashResultString    := HashClass.DigestAsString;

    ResultCalculated := string(BytesToRawString(TFormat_HEXL.Encode(HashResult)));
    ResultExpected   := string(FTestData[i].ExpectedOutput);

    CheckEquals(ResultExpected,
                ResultCalculated,
                HashClass.ClassName + ' Index: '+IntToStr(i));

    CheckEquals(ResultExpected,
                string(TFormat_HEXL.Encode(HashResultRawString)),
                'RawByteString: ' + HashClass.ClassName + ' Index: '+IntToStr(i));

    CheckEquals(StringOf(TFormat_HEXL.Decode(BytesOf(ResultExpected))),
                HashResultString,
                'String: ' + HashClass.ClassName + ' Index: '+IntToStr(i));
  end;
end;

procedure THash_TestBase.DoTestCalcBuffer(HashClass: TDECHash);
var
  i                : Integer;
  Buf              : TBytes;
  ResultBuf        : TBytes;
  RawByteStrResult : RawByteString;
begin
  for i := 0 to FTestData.Count-1 do
  begin
    ConfigHashClass(HashClass, i);

    Buf := BytesOf(RawByteString(FTestData[i].InputData));
    if Length(Buf) > 0 then
    begin
      ResultBuf := TFormat_HEXL.Encode(HashClass.CalcBuffer(Buf[0], Length(Buf)));
      RawByteStrResult := BytesToRawString(ResultBuf);

      CheckEquals(FTestData[i].ExpectedOutput,
                  RawByteStrResult,
                  'Index: ' + IntToStr(i) + ' - expected: <' +
                  string(FTestData[i].ExpectedOutput) + '> but was: <' +
                  string(RawByteStrResult) + '>');
    end
    else
    begin
      ResultBuf := TFormat_HEXL.Encode(HashClass.CalcBuffer(Buf, Length(Buf)));
      RawByteStrResult := BytesToRawString(ResultBuf);

      CheckEquals(FTestData[i].ExpectedOutput,
                  RawByteStrResult,
                  'Index: ' + IntToStr(i) + ' - expected: <' +
                  string(FTestData[i].ExpectedOutput) + '> but was: <' +
                  string(RawByteStrResult) + '>');
    end;
  end;
end;

procedure THash_TestBase.DoTestCalcBytes(HashClass: TDECHash);
var
  i                : Integer;
  RawByteStrResult : RawByteString;
  ResultBuf        : TBytes;
begin
  for i := 0 to FTestData.Count-1 do
  begin
    ConfigHashClass(HashClass, i);

    ResultBuf := HashClass.CalcBytes(BytesOf(RawByteString(FTestData[i].InputData)));
    RawByteStrResult := BytesToRawString(TFormat_HEXL.Encode(ResultBuf));

    CheckEquals(FTestData[i].ExpectedOutput,
                RawByteStrResult,
                'Index: ' + IntToStr(i) + ' - expected: <' +
                string(FTestData[i].ExpectedOutput) + '> but was: <' +
                string(RawByteStrResult) + '>');
  end;
end;

procedure THash_TestBase.DoTestCalcUnicodeString(HashClass: TDECHash);
var
  i                : Integer;
  InpStr           : string;
  RawByteStrResult : RawByteString;
  StrResult        : string;
begin
  for i := 0 to FTestData.Count-1 do
  begin
    if FTestData[i].RunUnicodeTest then
    begin
      InpStr := string(FTestData[i].InputData);
      ConfigHashClass(HashClass, i);

      StrResult := HashClass.CalcString(InpStr);
      RawByteStrResult := BytesToRawString(
                            TFormat_HEXL.Encode(
                              System.SysUtils.BytesOf(StrResult)));

      CheckEquals(FTestData[i].ExpectedOutputUTFStrTest,
                  RawByteStrResult,
                  'Index: ' + IntToStr(i) + ' - expected: <' +
                  string(FTestData[i].ExpectedOutputUTFStrTest) + '> but was: <' +
                  string(RawByteStrResult) + '> Input: <' + TFormat_HEXL.Encode(InpStr) + '>');
    end;
  end;
end;

procedure THash_TestBase.DoTestClassByName(ExpectedClassName: String; ExpectedClass: TClass);
var
  ReturnValue : TDECHashClass;
begin
  ReturnValue := FHash.ClassByName(ExpectedClassName);
  CheckEquals(ExpectedClass, ReturnValue, 'unexpected class');
end;

procedure THash_TestBase.Setup;
begin
  inherited;
  FTestData  := CreateTestDataContainer as IHashTestDataContainer;
end;

procedure THash_TestBase.TearDown;
begin
  inherited;
  FHash.Free;
  FTestData := nil;
end;

procedure THash_TestBase.Test52;
begin
  DoTest52(FHash);
end;

procedure THash_TestBase.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash);
end;

procedure THash_TestBase.TestCalcBytes;
begin
  DoTestCalcBytes(FHash);
end;

procedure THash_TestBase.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash);
end;

procedure THash_TestBase.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash);
end;

procedure THash_TestBase.TestGetPaddingByte;
begin
  CheckEquals(0, FHash.PaddingByte, 'Default padding byte is wrong');
end;

procedure THash_TestBase.TestIsPasswordHash;
begin
  CheckEquals(false, FHash.IsPasswordHash);
end;

procedure THash_TestBase.TestIsPasswordHashBase;
begin
  CheckEquals(false, TDECHash.IsPasswordHash);
end;

procedure THash_TestBase.TestClassByIdentity;
var
  ReturnValue: TDECClass;
begin
  ReturnValue := TDECHash.ClassByIdentity(THash_MD5.Identity);
  CheckEquals(ReturnValue, THash_MD5);

  ReturnValue := TDECHash.ClassByIdentity(THash_SHA256.Identity);
  CheckEquals(ReturnValue, THash_SHA256);
end;

procedure THash_TestBase.TestUninitializedException;
begin
  CheckException(DoTestUninitializedException, EDECHashException,
                 'Uninitialized hash not detected');
end;

procedure THash_TestBase.DoTestUninitializedException;
var
  Hash : THash_MD5;
  Buf  : TBytes;
begin
  Hash := THash_MD5.Create;
  try
    SetLength(Buf, 3);
    FillChar(Buf[0], 3, 33);
    Hash.Calc(Buf[0], 3);
  finally
    Hash.Free;
  end;
end;

procedure THash_TestBase.DoTestCalcRawByteString(HashClass: TDECHash);
var
  i                : Integer;
  RawByteStrResult : RawByteString;
begin
  for i := 0 to FTestData.Count-1 do
    begin
      ConfigHashClass(HashClass, i);

      RawByteStrResult := HashClass.CalcString(FTestData[i].InputData, TFormat_HEXL);

      CheckEquals(FTestData[i].ExpectedOutput,
                  RawByteStrResult,
                  'Index: ' + IntToStr(i) + ' - expected: <' +
                  string(FTestData[i].ExpectedOutput) + '> but was: <' +
                  string(RawByteStrResult) + '>');
    end;
end;

{ THash_TestBaseExtended }

procedure THash_TestBaseExtended.DoTestCalcStream(HashClass: TDECHashExtended);
var
  Stream           : TMemoryStream;
  i                : Integer;
  Buf              : TBytes;
  Hash             : TBytes;
  ProgressCalled   : Boolean;
  RawByteStrResult : RawByteString;
  BufSize          : Integer;
begin
  Stream  := TMemoryStream.Create;
  BufSize := 0;

  try
    for i := 0 to FTestData.Count-1 do
      begin
        Buf := BytesOf(FTestData[i].InputData);
        Stream.Clear;
        {$IF CompilerVersion >= 25.0}
        Stream.Write(Buf, Length(Buf));
        {$ELSE}
        if Length(Buf) > 0 then
          Stream.Write(Buf[0], Length(Buf));
        {$IFEND}
        Stream.Position := 0;

        ConfigHashClass(HashClass, i);

        // for the last test do set a negative value for the stream buffer size
        // in order to test that the default set within CalcStream works
        if (i = FTestData.Count-1) then
        begin
          BufSize          := StreamBufferSize;
          StreamBufferSize := -1;
        end;

        ProgressCalled := false;
        HashClass.CalcStream(Stream, Length(Buf), Hash,
                              procedure(Size, Pos: Int64; State: TDECProgressState)
                              begin
                                ProgressCalled := true;
                              end);


        if (i = FTestData.Count-1) then
          StreamBufferSize := BufSize;

        RawByteStrResult := BytesToRawString(TFormat_HEXL.Encode(Hash));

        CheckEquals(FTestData[i].ExpectedOutput,
                    RawByteStrResult,
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].ExpectedOutput) + '> but was: <' +
                    string(RawByteStrResult) + '>');

        CheckEquals(true, ProgressCalled, 'Progress event not called');

        ProgressCalled := false;
        Stream.Seek(0, TSeekOrigin.soBeginning);
        HashClass.CalcStream(Stream, -1, Hash,
                              procedure(Size, Pos: Int64; State: TDECProgressState)
                              begin
                                ProgressCalled := true;
                              end);

        if (i = FTestData.Count-1) then
          StreamBufferSize := BufSize;

        RawByteStrResult := BytesToRawString(TFormat_HEXL.Encode(Hash));
        CheckEquals(FTestData[i].ExpectedOutput,
                    RawByteStrResult,
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].ExpectedOutput) + '> but was: <' +
                    string(RawByteStrResult) + '>');

        CheckEquals(true, ProgressCalled, 'Progress event not called');
      end;
  finally
    Stream.Free;
  end;
end;

procedure THash_TestBaseExtended.DoTestCalcStreamNoDone(HashClass: TDECHashExtended);
var
  Stream           : TMemoryStream;
  i                : Integer;
  Buf              : TBytes;
  Hash             : TBytes;
  ProgressCalled   : Boolean;
  RawByteStrResult : RawByteString;
  BufSize          : Integer;
begin
  Stream  := TMemoryStream.Create;
  BufSize := 0;

  try
    for i := 0 to FTestData.Count-1 do
      begin
        Buf := BytesOf(FTestData[i].InputData);
        Stream.Clear;
        {$IF CompilerVersion >= 25.0}
        Stream.Write(Buf, Length(Buf));
        {$ELSE}
        if Length(Buf) > 0 then
          Stream.Write(Buf[0], Length(Buf));
        {$IFEND}
        Stream.Position := 0;

        ConfigHashClass(HashClass, i);

        // for the last test do set a negative value for the stream buffer size
        // in order to test that the default set within CalcStream works
        if (i = FTestData.Count-1) then
        begin
          BufSize          := StreamBufferSize;
          StreamBufferSize := -1;
        end;

        ProgressCalled := false;
        HashClass.Init;
        HashClass.CalcStream(Stream, Length(Buf),
                              procedure(Size, Pos: Int64; State: TDECProgressState)
                              begin
                                ProgressCalled := true;
                              end, true);

        Hash := HashClass.DigestAsBytes;

        if (i = FTestData.Count-1) then
          StreamBufferSize := BufSize;

        RawByteStrResult := BytesToRawString(TFormat_HEXL.Encode(Hash));
        CheckEquals(FTestData[i].ExpectedOutput,
                    RawByteStrResult,
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].ExpectedOutput) + '> but was: <' +
                    string(RawByteStrResult) + '>');

        CheckEquals(true, ProgressCalled, 'Progress event not called');

        ProgressCalled := false;
        Stream.Seek(0, TSeekOrigin.soBeginning);
        HashClass.Init;
        HashClass.CalcStream(Stream, -1,
                              procedure(Size, Pos: Int64; State: TDECProgressState)
                              begin
                                ProgressCalled := true;
                              end, true);

        Hash := HashClass.DigestAsBytes;

        if (i = FTestData.Count-1) then
          StreamBufferSize := BufSize;

        RawByteStrResult := BytesToRawString(TFormat_HEXL.Encode(Hash));
        CheckEquals(FTestData[i].ExpectedOutput,
                    RawByteStrResult,
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].ExpectedOutput) + '> but was: <' +
                    string(RawByteStrResult) + '>');

        CheckEquals(true, ProgressCalled, 'Progress event not called');
      end;
  finally
    Stream.Free;
  end;
end;

procedure THash_TestBaseExtended.DoTestCalcStreamNoDoneMulti(HashClass: TDECHashExtended);
var
  Stream           : TMemoryStream;
  i, n             : Integer;
  Buf              : TBytes;
  Hash             : TBytes;
  ProgressCalled   : Boolean;
  BufSize          : Integer;
  Count            : Integer;
  IsLastByte       : Boolean;
  Idx, CopyCount   : Integer;
  RawByteStrResult : RawByteString;
begin
  Stream  := TMemoryStream.Create;
  BufSize := 0;

  try
    for i := 0 to FTestData.Count-1 do
      begin
        Buf := BytesOf(FTestData[i].InputData);
        ConfigHashClass(HashClass, i);
        HashClass.Init;

        // for the last test do set a negative value for the stream buffer size
        // in order to test that the default set within CalcStream works
        if (i = FTestData.Count-1) then
        begin
          BufSize          := StreamBufferSize;
          StreamBufferSize := -1;
        end;

        Count := Length(Buf);
        Stream.Clear;

        n := 0;
        idx := 0;
        CopyCount := 1;
        while (n <= Count - 1) do
        begin
          Stream.Write(Buf[idx], CopyCount);
          Stream.Seek(-CopyCount, TSeekOrigin.soCurrent);

          IsLastByte := not (Count-n > 1);

          ProgressCalled := false;
          HashClass.CalcStream(Stream, CopyCount,
                                procedure(Size, Pos: Int64; State: TDECProgressState)
                                begin
                                  ProgressCalled := true;
                                end, IsLastByte);

          inc(idx, CopyCount);

          if ((n + 4) <= (Count - 1)) then
          begin
            inc(n, 4);
            CopyCount := 4;
          end
          else
          begin
            inc(n, 1);
            CopyCount := 1;
          end;
        end;

        // if we have empty input something still might be needed to be done
        if (Count = 0) then
          HashClass.CalcStream(Stream, 0,
                                procedure(Size, Pos: Int64; State: TDECProgressState)
                                begin
                                  ProgressCalled := true;
                                end, true);

        Hash := HashClass.DigestAsBytes;

        if (i = FTestData.Count-1) then
          StreamBufferSize := BufSize;

        RawByteStrResult := BytesToRawString(TFormat_HEXL.Encode(Hash));
        CheckEquals(FTestData[i].ExpectedOutput,
                    RawByteStrResult,
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].ExpectedOutput) + '> but was: <' +
                    string(RawByteStrResult) + '>');

        CheckEquals(true, ProgressCalled, 'Progress event not called');
      end;
  finally
    Stream.Free;
  end;
end;

procedure THash_TestBaseExtended.DoTestCalcStreamRawByteString(HashClass: TDECHashExtended);
var
  Stream : TMemoryStream;
  i      : Integer;
  Buf    : TBytes;
  Hash   : RawByteString;
  ProgressCalled : Boolean;

  BufSize: Integer;
begin
  Stream  := TMemoryStream.Create;
  BufSize := 0;

  try
    for i := 0 to FTestData.Count-1 do
      begin
        Buf := BytesOf(FTestData[i].InputData);
        Stream.Clear;
        {$IF CompilerVersion >= 25.0}
        Stream.Write(Buf, Length(Buf));
        {$ELSE}
        if Length(Buf) > 0 then
          Stream.Write(Buf[0], Length(Buf));
        {$IFEND}
        Stream.Position := 0;

        ConfigHashClass(HashClass, i);

        // for the last test do set a negative value for the stream buffer size
        // in order to test that the default set within CalcStream works
        if (i = FTestData.Count-1) then
        begin
          BufSize          := StreamBufferSize;
          StreamBufferSize := -1;
        end;

        ProgressCalled := false;
        Hash := HashClass.CalcStream(Stream, Length(Buf), TFormat_HexL,
                                     procedure(Size, Pos: Int64; State: TDECProgressState)
                                     begin
                                       ProgressCalled := true;
                                     end);


        if (i = FTestData.Count-1) then
          StreamBufferSize := BufSize;

        CheckEquals(FTestData[i].ExpectedOutput,
                    Hash,
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].ExpectedOutput) + '> but was: <' +
                    string(Hash) + '>');

        CheckEquals(true, ProgressCalled, 'Progress event not called');
      end;
  finally
    Stream.Free;
  end;
end;

procedure THash_TestBaseExtended.TestCalcStream;
begin
  DoTestCalcStream(FHash as TDECHashExtended);
end;

procedure THash_TestBaseExtended.TestCalcStreamNoDone;

begin
  DoTestCalcStreamNoDone(FHash  as TDECHashExtended);
end;

procedure THash_TestBaseExtended.TestCalcStreamNoDoneMulti;
begin
  DoTestCalcStreamNoDoneMulti(FHash as TDECHashExtended);
end;

procedure THash_TestBaseExtended.TestCalcStreamRawByteString;
begin
  DoTestCalcStreamRawByteString(FHash  as TDECHashExtended);
end;

{ TestTDECHash }


procedure TestTDECHash.TestIsClassListCreated;
begin
  CheckEquals(true, assigned(TDECHash.ClassList), 'Class list has not been created in initialization');
end;

procedure TestTDECHash.TestValidCipherSetDefaultHashClass;
var
  result : Boolean;
begin
  // Asumption: nobody has called SetDefaultHash yet so DECHash' initialization
  // of THash_SHA256 is in effect
  result := ValidHash(nil) = THash_SHA256;
  CheckEquals(true, result, 'Initial default hash is not THash_SHA256');

  try
    SetDefaultHashClass(THash_Haval160);
    result := ValidHash(nil) = THash_Haval160;
    CheckEquals(true, result, 'Changed default cipher is not THash_Haval160');

    SetDefaultHashClass(THash_Haval192);
    result := ValidHash(nil) = THash_Haval192;
    CheckEquals(true, result, 'Changed default cipher is not THash_Haval192');

    result := ValidHash(THash_Square) = THash_Square;
    CheckEquals(true, result, 'Passed cipher is not THash_Square');
  finally
    SetDefaultHashClass(THash_SHA256);
  end;
end;

{ TDECHashUnitTest }

class function TDECHashIncrement8.BlockSize: UInt32;
begin
  result := 4;
end;

function TDECHashIncrement8.Digest: PByteArray;
begin
  // Returns nil on purpose to supress a return value might be undefined warning
  result := nil;
end;

class function TDECHashIncrement8.DigestSize: UInt32;
begin
  result := 0;
end;

procedure TDECHashIncrement8.DoDone;
begin
  // Empty on purpose
end;

procedure TDECHashIncrement8.DoInit;
begin
  // Empty on purpose
end;

procedure TDECHashIncrement8.DoTransform(Buffer: PUInt32Array);
begin
  // Empty on purpose
end;

procedure TDECHashIncrement8.Increment8(var Value; Add: UInt32);
begin
  inherited Increment8(Value, Add);
end;

{ THash_TestIncrement8 }

procedure THash_TestIncrement8.SetUp;
begin
  inherited;
  FHashIncr8 := TDECHashIncrement8.Create;
  FHashIncr8.Init;
end;

procedure THash_TestIncrement8.TearDown;
begin
  FHashIncr8.Free;
  inherited;
end;

procedure THash_TestIncrement8.TestIncrement8;
var
  i, n : Integer;
begin
  for i := 1 to 255 do
  begin
    n := i;
    FHashIncr8.Increment8(n, 1);
    CheckEquals(i + 8, n);
  end;
end;

{ THash_TestCPPBuilderExceptions }

procedure THash_TestCPPBuilderExceptions.DoTestBlockSizeException;
var
  Result : UInt32;
begin
  Result := TDECHash.BlockSize;
  CheckEquals(0, Result, 'Dummy check which should never get reached due to ' +
                         'the exception being raised before');
end;

procedure THash_TestCPPBuilderExceptions.DoTestDigestSizeException;
var
  Result : UInt32;
begin
  Result := TDECHash.DigestSize;
  CheckEquals(0, Result, 'Dummy check which should never get reached due to ' +
                         'the exception being raised before');
end;

procedure THash_TestCPPBuilderExceptions.SetUp;
begin
  // Empty on purpose as only class functions are tested
  inherited;
end;

procedure THash_TestCPPBuilderExceptions.TearDown;
begin
  // Empty on purpose as only class functions are tested
  inherited;
end;

procedure THash_TestCPPBuilderExceptions.TestBlockSizeException;
begin
  CheckException(DoTestBlockSizeException, EDECAbstractError,
                 'Abstract error raised for C++ Builder not detected');
end;

procedure THash_TestCPPBuilderExceptions.TestDigestSizeException;
begin
  CheckException(DoTestDigestSizeException, EDECAbstractError,
                 'Abstract error raised for C++ Builder not detected');
end;

{ TestTHash_BCrypt }

procedure TestTHash_BCrypt.ConfigHashClass(aHashClass: TDECHash;
  aIdxTestData: Integer);
begin
  inherited;
  THash_BCrypt(FHash).Cost := FTestData[aIdxTestData].Cost;
  THash_BCrypt(FHash).Salt := FTestData[aIdxTestData].Salt;
end;

procedure TestTHash_BCrypt.DoTestCostFactorTooLongException;
begin
  THash_BCrypt(FHash).Cost := 32;
end;

procedure TestTHash_BCrypt.DoTestCostFactorTooShortException;
begin
  THash_BCrypt(FHash).Cost := 3;
end;

procedure TestTHash_BCrypt.DoTestNoSaltSpecified;
var
  BCrypt : THash_BCrypt;
begin
  BCrypt := THash_BCrypt.Create;
  try
    BCrypt.Init;
    BCrypt.Cost := 8;
    BCrypt.CalcString('a');
  finally
    BCrypt.Free;
  end;
end;

procedure TestTHash_BCrypt.DoTestTooLongPasswordSpecified;
var
  BCrypt   : THash_BCrypt;
  Password : TBytes;
  i        : Integer;
begin
  BCrypt := THash_BCrypt.Create;
  try
    BCrypt.Init;
    BCrypt.Cost := 8;
    BCrypt.Salt := [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    SetLength(Password, BCrypt.MaxPasswordLength + 1);
    for i := Low(Password) to High(Password) do
      Password[i] := i;

    BCrypt.CalcBytes(Password);
  finally
    BCrypt.Free;
  end;
end;

procedure TestTHash_BCrypt.DoTestTooLongSaltSpecified;
var
  BCrypt : THash_BCrypt;
begin
  BCrypt := THash_BCrypt.Create;
  try
    BCrypt.Init;
    BCrypt.Cost := 8;
    // One byte too long
    BCrypt.Salt := [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
    BCrypt.CalcString('a');
  finally
    BCrypt.Free;
  end;
end;

procedure TestTHash_BCrypt.DoTestTooShortSaltSpecified;
var
  BCrypt : THash_BCrypt;
begin
  BCrypt := THash_BCrypt.Create;
  try
    BCrypt.Init;
    BCrypt.Cost := 8;
    // One byte too short
    BCrypt.Salt := [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    BCrypt.CalcString('a');
  finally
    BCrypt.Free;
  end;
end;

procedure TestTHash_BCrypt.SetUp;
var
  lDataRow:IHashTestDataRowSetup;
begin
  inherited;

  FHash := THash_BCrypt.Create;

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '557e94f34bf286e8719a26be94ac1e16d95ef9f819dee0';
  lDataRow.ExpectedOutputUTFStrTest := '557e94f34bf286e8719a26be94ac1e16d95ef9f819dee0';
  lDataRow.Cost                     := 6;
  lDataRow.Salt                     := [$14, $4b, $3d, $69, $1a, $7b, $4e, $cf, $39, $cf, $73, $5c, $7f, $a7, $a7, $9c];
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '56701b26164d8f1bc15225f46234ac8ac79bf5bc16bf48';
  lDataRow.ExpectedOutputUTFStrTest := '56701b26164d8f1bc15225f46234ac8ac79bf5bc16bf48';
  lDataRow.Cost                     := 8;
  lDataRow.Salt                     := [$26, $c6, $30, $33, $c0, $4f, $8b, $cb, $a2, $fe, $24, $b5, $74, $db, $62, $74];
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '7b2e03106a43c9753821db688b5cc7590b18fdf9ba5446';
  lDataRow.ExpectedOutputUTFStrTest := '7b2e03106a43c9753821db688b5cc7590b18fdf9ba5446';
  lDataRow.Cost                     := 10;
  lDataRow.Salt                     := [$9b, $7c, $9d, $2a, $da, $0f, $d0, $70, $91, $c9, $15, $d1, $51, $77, $01, $d6];
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '6b42a6771693c6a7f576174cdfe514b9a004b8a4919f34';
  lDataRow.ExpectedOutputUTFStrTest := '6b42a6771693c6a7f576174cdfe514b9a004b8a4919f34';
  lDataRow.Cost                     := 12;
  lDataRow.Salt                     := [$9b, $ae, $1b, $1c, $91, $d8, $b0, $3a, $f9, $c5, $89, $e4, $02, $92, $a9, $fb];
  lDataRow.AddInputVector('');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'e6d53831f82060dc08a2e8489ce850ce48fbf976978738';
  lDataRow.ExpectedOutputUTFStrTest := 'f3ebc852f57e9a750eef2a7f69722cdb0ffd7c6128387a';
  lDataRow.Cost                     := 6;
  lDataRow.Salt                     := [$a3, $61, $2d, $8c, $9a, $37, $da, $c2, $f9, $9d, $94, $da, $03, $bd, $45, $21];
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'a9f3469a61cbff0a0f1a1445dfe023587f38b2c9c40570';
  lDataRow.ExpectedOutputUTFStrTest := 'c5f17162d049b91005ae47f279507acc1f11776e9ee509';
  lDataRow.Cost                     := 8;
  lDataRow.Salt                     := [$7a, $17, $b1, $5d, $fe, $1c, $4b, $e1, $0e, $c6, $a3, $ab, $47, $81, $83, $86];
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '5169fd39606d630524285147734b4c981def0ee512c3ac';
  lDataRow.ExpectedOutputUTFStrTest := '06132df02bcfdcce8a69a03eee7d3b7aafbc8d49161936';
  lDataRow.Cost                     := 10;
  lDataRow.Salt                     := [$9b, $ef, $4d, $04, $e1, $f8, $f9, $2f, $3d, $e5, $73, $23, $f8, $17, $91, $90];
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd7678c2595f3a31cca9ded7dfbbc7308a6ed92325bae05';
  lDataRow.ExpectedOutputUTFStrTest := '816480f1d2e7aa106f4ab04387e5ce1e3864da8e1b2223';
  lDataRow.Cost                     := 12;
  lDataRow.Salt                     := [$f8, $f2, $c9, $e4, $db, $91, $b4, $23, $d4, $bd, $7f, $19, $bc, $37, $26, $12];
  lDataRow.AddInputVector('a');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd9a275b493bcbe1024b0ff80d330253cfdca34687d8f69';
  lDataRow.ExpectedOutputUTFStrTest := '1dff5b90e45ba4579b988de2cf39711b98345884ef7fba';
  lDataRow.Cost                     := 6;
  lDataRow.Salt                     := [$2a, $1f, $1d, $c7, $0a, $3d, $14, $79, $56, $a4, $6f, $eb, $e3, $01, $60, $17];
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8d4131a723bfbbac8a67f2e035cae08cc33b69f37331ea';
  lDataRow.ExpectedOutputUTFStrTest := '69b48ee000e242c13a38e577dc64f07781fc9f71443618';
  lDataRow.Cost                     := 8;
  lDataRow.Salt                     := [$4e, $ad, $84, $5a, $14, $2c, $9b, $c7, $99, $18, $c8, $79, $7f, $47, $0e, $f5];
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '8cd0b863c3ff0860e31a2b42427974e0283b3af7142969';
  lDataRow.ExpectedOutputUTFStrTest := '2eb7349e00af01d911e0b21b3a0688210fe455ac920563';
  lDataRow.Cost                     := 10;
  lDataRow.Salt                     := [$63, $1c, $55, $44, $93, $32, $7c, $32, $f9, $c2, $6d, $9b, $e7, $d1, $8e, $4c];
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '398fc08825ec73f80d5370414dabda1280f780d26203fb';
  lDataRow.ExpectedOutputUTFStrTest := '4636ae292eb20a6a1c52f1c2b175078504b41c631611ed';
  lDataRow.Cost                     := 12;
  lDataRow.Salt                     := [$19, $94, $e6, $86, $67, $e8, $66, $9e, $22, $d5, $fb, $b8, $51, $49, $2f, $c0];
  lDataRow.AddInputVector('abc');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '4d38b523ce9dc6f2f6ff9fb3c2cd71dfe7f96eb4a3baf1';
  lDataRow.ExpectedOutputUTFStrTest := 'f0cb2b9fe94c95761ec9526131b8f9dd25441454e49466';
  lDataRow.Cost                     := 6;
  lDataRow.Salt                     := [$02, $d1, $17, $6d, $74, $15, $8e, $e2, $9c, $ff, $da, $c6, $15, $0c, $f1, $23];
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '98bf9ffc1f5be485f959e8b1d526392fbd4ed2d5719f50';
  lDataRow.ExpectedOutputUTFStrTest := 'f909cb8d2e60537b7932ad6d0863b55a8d0a2fc3cdf254';
  lDataRow.Cost                     := 8;
  lDataRow.Salt                     := [$71, $5b, $96, $ca, $ed, $2a, $c9, $2c, $35, $4e, $d1, $6c, $1e, $19, $e3, $8a];
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'cebba53f67bd28af5a44c6707383c231ac4ef244a6f5fb';
  lDataRow.ExpectedOutputUTFStrTest := 'd66afd696bfc0ebb2a8ca33b708c834f602789d4a801e4';
  lDataRow.Cost                     := 10;
  lDataRow.Salt                     := [$85, $72, $7e, $83, $8f, $90, $49, $39, $7f, $be, $c9, $05, $66, $ed, $e0, $df];
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '498c11e6b9ad6ed402a6c44076883574ea62012c8b06b2';
  lDataRow.ExpectedOutputUTFStrTest := '906c4fb134790125e3b9963318fc684c9d43c28fe814d3';
  lDataRow.Cost                     := 12;
  lDataRow.Salt                     := [$17, $a2, $3b, $87, $7f, $aa, $f5, $c3, $8e, $87, $27, $2e, $0c, $df, $48, $af];
  lDataRow.AddInputVector('abcdefghijklmnopqrstuvwxyz');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := '26f517fe5345ad575ba7dfb8144f01bfdb15f3d47c1e14';
  lDataRow.ExpectedOutputUTFStrTest := '56c059831b5311bacc275e1f6b5ff6855f6e6edc752e56';
  lDataRow.RunUnicodeTest           := true;
  lDataRow.Cost                     := 6;
  lDataRow.Salt                     := [$85, $12, $ae, $0d, $0f, $ac, $4e, $c9, $a5, $97, $8f, $79, $b6, $17, $10, $28];
  lDataRow.AddInputVector('~!@#$%^&*()      ~!@#$%^&*()PNBFRD');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'd51d7cdf839b91a25758b80141e42c9f896ae80fd6cd56';
  lDataRow.ExpectedOutputUTFStrTest := '4f019a19393508796b1ad5ecd4f344711e0d49e956e65d';
  lDataRow.RunUnicodeTest           := true;
  lDataRow.Cost                     := 8;
  lDataRow.Salt                     := [$1a, $ce, $2d, $e8, $80, $7d, $f1, $8c, $79, $fc, $ed, $54, $67, $8f, $38, $8f];
  lDataRow.AddInputVector('~!@#$%^&*()      ~!@#$%^&*()PNBFRD');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'db4fab24c1ff41c1e2c966f8b3d6381c76e86f52da9e15';
  lDataRow.ExpectedOutputUTFStrTest := 'b6efcca9da72b95671d5bc0a663ed6db745e89daed94ab';
  lDataRow.RunUnicodeTest           := true;
  lDataRow.Cost                     := 10;
  lDataRow.Salt                     := [$36, $28, $5a, $62, $67, $75, $1b, $14, $ba, $2d, $c9, $89, $f6, $d4, $31, $26];
  lDataRow.AddInputVector('~!@#$%^&*()      ~!@#$%^&*()PNBFRD');

  lDataRow := FTestData.AddRow;
  lDataRow.ExpectedOutput           := 'b7af3ca87144725e9df096b9199231873a3ae6e8348e21';
  lDataRow.ExpectedOutputUTFStrTest := '73ddc38d3e8f0b87b04f8bb1fe04bf728e507e78e2dcd0';
  lDataRow.RunUnicodeTest           := true;
  lDataRow.Cost                     := 12;
  lDataRow.Salt                     := [$60, $2a, $f5, $a5, $64, $0b, $86, $61, $88, $52, $86, $93, $86, $99, $ad, $45];
  lDataRow.AddInputVector('~!@#$%^&*()      ~!@#$%^&*()PNBFRD');
end;

function TestTHash_BCrypt.SplitTestVector(const Vector: string): TBCryptBSDTestData;
var
  Parts : TArray<string>;
begin
  Parts := Vector.Split(['$'], TStringSplitOptions.ExcludeEmpty);
  Result.Cost := Copy(Parts[1], Low(Parts[1]), Length(Parts[1])).ToInteger;
  Result.Salt := Copy(Parts[2], Low(Parts[2]), 22);
end;

procedure TestTHash_BCrypt.TestBlockSize;
begin
  CheckEquals(8, FHash.BlockSize);
end;

procedure TestTHash_BCrypt.TestClassByName;
begin
  DoTestClassByName('THash_BCrypt', THash_BCrypt);
end;

procedure TestTHash_BCrypt.TestCostFactorTooLongException;
begin
  CheckException(DoTestCostFactorTooLongException, EDECHashException);
end;

procedure TestTHash_BCrypt.TestCostFactorTooShortException;
begin
  CheckException(DoTestCostFactorTooShortException, EDECHashException);
end;

procedure TestTHash_BCrypt.TestCreateCryptBSDFormatString;
var
  Result    : string;
  i         : Integer;
  SplitData : TBCryptBSDTestData;
  HashInst  : THash_BCrypt;
begin
  HashInst := THash_BCrypt.Create;
  try
    for i := Low(TestData) to High(TestData) do
    begin
      SplitData := SplitTestVector(TestData[i].CryptData);
      Result := HashInst.GetDigestInCryptFormat(Passwords[TestData[i].PWNum],
                                                SplitData.Cost.ToString,
                                                SplitData.Salt,
                                                False,
                                                TFormat_BCryptBSD);

      CheckEquals(TestData[i].CryptData, Result);
    end;
  finally
    HashInst.Free;
  end;
end;

procedure TestTHash_BCrypt.TestCreateCryptBSDFormatTBytes;
var
  Result    : string;
  i         : Integer;
  SplitData : TBCryptBSDTestData;
  HashInst  : THash_BCrypt;
begin
  HashInst := THash_BCrypt.Create;
  try
    for i := Low(TestData) to High(TestData) do
    begin
      SplitData := SplitTestVector(TestData[i].CryptData);
      Result := HashInst.GetDigestInCryptFormat(
                  TEncoding.UTF8.GetBytes(Passwords[TestData[i].PWNum]),
                  SplitData.Cost.ToString,
                  SplitData.Salt,
                  False,
                  TFormat_BCryptBSD);

      CheckEquals(TestData[i].CryptData, Result);
    end;
  finally
    HashInst.Free;
  end;
end;

procedure TestTHash_BCrypt.TestDigestSize;
begin
  CheckEquals(23, FHash.DigestSize);
end;

procedure TestTHash_BCrypt.TestIdentity;
begin
  CheckEquals($9CA55338, FHash.Identity);
end;

procedure TestTHash_BCrypt.TestIsPasswordHash;
begin
  CheckEquals(true, FHash.IsPasswordHash);
end;

procedure TestTHash_BCrypt.TestIsValidPasswordFalseString;
var
  Result    : Boolean;
  HashInst  : THash_BCrypt;
begin
  HashInst := THash_BCrypt.Create;
  try
    Result := HashInst.IsValidPassword('a',
                                       '1234567890123456789012345678901234567' +
                                       '8901234567890123456789',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failure at wrong CryptData length');

    Result := HashInst.IsValidPassword('a',
                                       TestData[1].CryptData,
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong password for empty password');

    Result := HashInst.IsValidPassword('ab',
                                       TestData[5].CryptData,
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong password for password a');

    Result := HashInst.IsValidPassword('a',
                                       '$3a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxe',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong CryptData format for ID');

    Result := HashInst.IsValidPassword('a',
                                       '$2a06$m0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxe',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong CryptData format for '+
                               'cost missing');

    Result := HashInst.IsValidPassword('a',
                                       '$2a$06m0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxe',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong CryptData format for '+
                               'salt missing');

    Result := HashInst.IsValidPassword('a',
                                       '$2a$06$n0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxe',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong password with wrong '+
                               'salt given');

    Result := HashInst.IsValidPassword('a',
                                       '$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxf',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong password with wrong '+
                               'password hash given');
  finally
    HashInst.Free;
  end;
end;

procedure TestTHash_BCrypt.TestIsValidPasswordFalseTBytes;
var
  Result    : Boolean;
  HashInst  : THash_BCrypt;
begin
  HashInst := THash_BCrypt.Create;
  try
    Result := HashInst.IsValidPassword([$61],
                                       '1234567890123456789012345678901234567' +
                                       '8901234567890123456789',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failure at wrong CryptData length');

    Result := HashInst.IsValidPassword([$61],
                                       TestData[1].CryptData,
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong password for empty password');

    Result := HashInst.IsValidPassword([$61, $62],
                                       TestData[5].CryptData,
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong password for password a');

    Result := HashInst.IsValidPassword([$61],
                                       '$3a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxe',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong CryptData format for ID');

    Result := HashInst.IsValidPassword([$61],
                                       '$2a06$m0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxe',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong CryptData format for '+
                               'cost missing');

    Result := HashInst.IsValidPassword([$61],
                                       '$2a$06m0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxe',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong CryptData format for '+
                               'salt missing');

    Result := HashInst.IsValidPassword([$61],
                                       '$2a$06$n0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxe',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong password with wrong '+
                               'salt given');

    Result := HashInst.IsValidPassword([$61],
                                       '$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2Kdee' +
                                       'WLuGmsfGlMfOxih58VYVfxf',
                                       TFormat_BCryptBSD);

    CheckEquals(false, Result, 'Failed to detect wrong password with wrong '+
                               'password hash given');
  finally
    HashInst.Free;
  end;
end;

procedure TestTHash_BCrypt.TestIsValidPasswordOKString;
var
  Result    : Boolean;
  i         : Integer;
  HashInst  : THash_BCrypt;
begin
  HashInst := THash_BCrypt.Create;
  try
    for i := Low(TestData) to High(TestData) do
    begin
      Result := HashInst.IsValidPassword(Passwords[TestData[i].PWNum],
                                         TestData[i].CryptData,
                                         TFormat_BCryptBSD);

      CheckEquals(true, Result, 'Failure at test data index: ' + i.ToString);
    end;
  finally
    HashInst.Free;
  end;
end;

procedure TestTHash_BCrypt.TestIsValidPasswordOKTBytes;
var
  Result    : Boolean;
  i         : Integer;
  HashInst  : THash_BCrypt;
begin
  HashInst := THash_BCrypt.Create;
  try
    for i := Low(TestData) to High(TestData) do
    begin
      Result := HashInst.IsValidPassword(
                  TEncoding.UTF8.GetBytes(Passwords[TestData[i].PWNum]),
                  TestData[i].CryptData,
                  TFormat_BCryptBSD);

      CheckEquals(true, Result, 'Failure at test data index: ' + i.ToString);
    end;
  finally
    HashInst.Free;
  end;
end;

procedure TestTHash_BCrypt.TestMaxCost;
begin
  CheckEquals(31, THash_BCrypt(FHash).MaxCost);
end;

procedure TestTHash_BCrypt.TestMaximumPasswordLength;
begin
  CheckEquals(72, TDECPasswordHash(FHash).MaxPasswordLength);
end;

procedure TestTHash_BCrypt.TestMaximumSaltLength;
begin
  CheckEquals(16, TDECPasswordHash(FHash).MaxSaltLength);
end;

procedure TestTHash_BCrypt.TestMinCost;
begin
  CheckEquals(4, THash_BCrypt(FHash).MinCost);
end;

procedure TestTHash_BCrypt.TestMinimumSaltLength;
begin
  CheckEquals(16, TDECPasswordHash(FHash).MinSaltLength);
end;

procedure TestTHash_BCrypt.TestNoSaltSpecified;
begin
  CheckException(DoTestNoSaltSpecified, EDECHashException);
end;

procedure TestTHash_BCrypt.TestSetGetCostFactor;
begin
  THash_BCrypt(FHash).Cost := 4;
  CheckEquals(4, THash_BCrypt(FHash).Cost);

  THash_BCrypt(FHash).Cost := 31;
  CheckEquals(31, THash_BCrypt(FHash).Cost);
end;

procedure TestTHash_BCrypt.TestTooLongPasswordException;
begin
  CheckException(DoTestTooLongPasswordSpecified, EDECHashException);
end;

procedure TestTHash_BCrypt.TestTooLongSaltSpecified;
begin
  CheckException(DoTestTooLongSaltSpecified, EDECHashException);
end;

procedure TestTHash_BCrypt.TestTooShortSaltSpecified;
begin
  CheckException(DoTestTooShortSaltSpecified, EDECHashException);
end;

{ THash_TestTDECPasswordHash }

procedure THash_TestTDECPasswordHash.DoTestClassByCryptIdentityException;
begin
  TDECPasswordHash.ClassByCryptIdentity('nwrongID');
end;

procedure THash_TestTDECPasswordHash.DoTestSaltTooLongException;
var
  EmptySalt : TBytes;
begin
  SetLength(EmptySalt, FHash.MaxSaltLength + 1);

  FHash.Salt := EmptySalt;
end;

procedure THash_TestTDECPasswordHash.DoTestSaltTooShortException;
var
  EmptySalt : TBytes;
begin
  SetLength(EmptySalt, FHash.MinSaltLength - 1);

  FHash.Salt := EmptySalt;
end;

procedure THash_TestTDECPasswordHash.SetUp;
begin
  inherited;

  FHash := THash_BCrypt.Create;
end;

procedure THash_TestTDECPasswordHash.TearDown;
begin
  FHash.Free;

  inherited;
end;

procedure THash_TestTDECPasswordHash.TestClassByCryptIdentityException;
begin
  CheckException(DoTestClassByCryptIdentityException, EDECCLassNotRegisteredException);
end;

procedure THash_TestTDECPasswordHash.TestClassByCryptIdentitySuccess;
var
  HashClass : TDECPasswordHashClass;
begin
  HashClass := TDECPasswordHash.ClassByCryptIdentity('2a');
  CheckEquals('THash_BCrypt', HashClass.ClassName);

  HashClass := TDECPasswordHash.ClassByCryptIdentity('2A');
  CheckEquals('THash_BCrypt', HashClass.ClassName);

  HashClass := TDECPasswordHash.ClassByCryptIdentity('$2a');
  CheckEquals('THash_BCrypt', HashClass.ClassName);

  HashClass := TDECPasswordHash.ClassByCryptIdentity('$2A');
  CheckEquals('THash_BCrypt', HashClass.ClassName);
end;

procedure THash_TestTDECPasswordHash.TestGetSalt;
var
  SetSalt, ActSalt : TBytes;
begin
  ActSalt := FHash.Salt;
  CheckEquals(0, Length(ActSalt));

  SetSalt := [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
  FHash.Salt := SetSalt;

  ActSalt := FHash.Salt;
  CheckEquals(true, System.SysUtils.CompareMem(@SetSalt[0], @ActSalt[0], Length(ActSalt)));
end;

procedure THash_TestTDECPasswordHash.TestSaltTooLongException;
var
  ActSalt : TBytes;
begin
  ActSalt := FHash.Salt;
  CheckEquals(0, Length(ActSalt));

  CheckException(DoTestSaltTooLongException, EDECHashException);

  ActSalt := FHash.Salt;
  CheckEquals(0, Length(ActSalt));
end;

procedure THash_TestTDECPasswordHash.TestSaltTooShortException;
var
  ActSalt : TBytes;
begin
  ActSalt := FHash.Salt;
  CheckEquals(0, Length(ActSalt));

  CheckException(DoTestSaltTooShortException, EDECHashException);

  ActSalt := FHash.Salt;
  CheckEquals(0, Length(ActSalt));
end;

procedure THash_TestTDECPasswordHash.TestSetSalt;
var
  SetSalt, ActSalt : TBytes;
begin
  SetSalt := [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
  FHash.Salt := SetSalt;

  ActSalt := FHash.Salt;
  CheckEquals(true, System.SysUtils.CompareMem(@SetSalt[0], @ActSalt[0], Length(ActSalt)));
end;

{ THash_TestPasswordBase }

procedure THash_TestPasswordBase.ConfigHashClass(aHashClass: TDECHash;
  aIdxTestData: Integer);
begin
  inherited;
  TDECPasswordHash(FHash).Salt := FTestData[aIdxTestData].Salt;
end;

initialization
  // Register any test cases with the test runner
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(THash_TestIncrement8);
  TDUnitX.RegisterTestFixture(THash_TestCPPBuilderExceptions);
  TDUnitX.RegisterTestFixture(THash_TestTDECPasswordHash);
  TDUnitX.RegisterTestFixture(TestTDECHash);
  TDUnitX.RegisterTestFixture(TestTHash_MD2);
  TDUnitX.RegisterTestFixture(TestTHash_MD4);
  TDUnitX.RegisterTestFixture(TestTHash_MD5);
  TDUnitX.RegisterTestFixture(TestTHash_RipeMD128);
  TDUnitX.RegisterTestFixture(TestTHash_RipeMD160);
  TDUnitX.RegisterTestFixture(TestTHash_RipeMD256);
  TDUnitX.RegisterTestFixture(TestTHash_RipeMD320);
  TDUnitX.RegisterTestFixture(TestTHash_SHA0);

  {$IFDEF OLD_SHA_NAME}
  TDUnitX.RegisterTestFixture(TestTHash_SHA);
  {$ENDIF}

  TDUnitX.RegisterTestFixture(TestTHash_SHA1);
  TDUnitX.RegisterTestFixture(TestTHash_SHA256);
  TDUnitX.RegisterTestFixture(TestTHash_SHA224);
  TDUnitX.RegisterTestFixture(TestTHash_SHA384);
  TDUnitX.RegisterTestFixture(TestTHash_SHA512);
  TDUnitX.RegisterTestFixture(TestTHash_Haval128);
  TDUnitX.RegisterTestFixture(TestTHash_Haval160);
  TDUnitX.RegisterTestFixture(TestTHash_Haval192);
  TDUnitX.RegisterTestFixture(TestTHash_Haval224);
  TDUnitX.RegisterTestFixture(TestTHash_Haval256);
  TDUnitX.RegisterTestFixture(TestTHash_Tiger_3Rounds);
  TDUnitX.RegisterTestFixture(TestTHash_Panama);

  TDUnitX.RegisterTestFixture(TestTHash_Whirlpool0);
  TDUnitX.RegisterTestFixture(TestTHash_WhirlpoolT);
  TDUnitX.RegisterTestFixture(TestTHash_Whirlpool1);

  {$IFDEF OLD_WHIRLPOOL_NAMES}
  TDUnitX.RegisterTestFixture(TestTHash_Whirlpool);
  {$ENDIF}

  TDUnitX.RegisterTestFixture(TestTHash_Square);
  TDUnitX.RegisterTestFixture(TestTHash_Snefru128);
  TDUnitX.RegisterTestFixture(TestTHash_Snefru256);
  TDUnitX.RegisterTestFixture(TestTHash_Sapphire);
  TDUnitX.RegisterTestFixture(TestTHash_BCrypt);
  {$ELSE}
  RegisterTests('DECHash', [THash_TestIncrement8.Suite,
                            THash_TestCPPBuilderExceptions.Suite,
                            THash_TestTDECPasswordHash.Suite,
                            TestTDECHash.Suite,
                            TestTHash_MD2.Suite,
                            TestTHash_MD4.Suite,
                            TestTHash_MD5.Suite,
                            TestTHash_RipeMD128.Suite,
                            TestTHash_RipeMD160.Suite,
                            TestTHash_RipeMD256.Suite,
                            TestTHash_RipeMD320.Suite,
                            TestTHash_SHA0.Suite,
                            {$IFDEF OLD_SHA_NAME}
                            TestTHash_SHA.Suite,
                            {$ENDIF}
                            TestTHash_SHA1.Suite,
                            TestTHash_SHA256.Suite,
                            TestTHash_SHA224.Suite,
                            TestTHash_SHA384.Suite,
                            TestTHash_SHA512.Suite,
                            TestTHash_Haval128.Suite,
                            TestTHash_Haval160.Suite,
                            TestTHash_Haval192.Suite,
                            TestTHash_Haval224.Suite,
                            TestTHash_Haval256.Suite,
                            TestTHash_Tiger_3Rounds.Suite,
                            TestTHash_Panama.Suite,

                            TestTHash_Whirlpool0.Suite,
                            TestTHash_WhirlpoolT.Suite,
                            TestTHash_Whirlpool1.Suite,

                            {$IFDEF OLD_WHIRLPOOL_NAMES}
                            TestTHash_Whirlpool.Suite,
                            {$ENDIF}

                            TestTHash_Square.Suite,
                            TestTHash_Snefru128.Suite,
                            TestTHash_Snefru256.Suite,
                            TestTHash_Sapphire.Suite,

                            TestTHash_BCrypt.Suite
                           ]);
  {$ENDIF}
end.
