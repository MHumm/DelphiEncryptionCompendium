unit TestDECTestDataContainer;

interface

type
  ITestDataInputVector = interface
  ['{CEC7AE49-DA2D-438A-BE8B-2BC2FA1DBCD0}']
    function GetRunCount:Cardinal;
    function GetData:RawByteString;

    property RunCount:Cardinal read GetRunCount;
    property Data:RawByteString read GetData;
  end;

  ITestDataInputVectorContainer = interface
  ['{34CEDD4B-4249-4C69-A0CC-C89F90A9B4E3}']
    function GetCount:Integer;
    function GetVectors(aIndex:Integer):ITestDataInputVector;

    property Count:Integer read GetCount;
    property Vectors[aIndex:integer]:ITestDataInputVector read GetVectors; default;

    function AddInputVector(const aData:RawByteString; const aRunCount:Cardinal=1;
                            const aConcatCount:Cardinal=1):ITestDataInputVector;
  end;

  ITestDataRow = interface
  ['{A105BADC-46E9-4A1D-B338-5C8E60305823}']
    function GetInputData:RawByteString;
    function GetInputVectors:ITestDataInputVectorContainer;
    function GetOutputData:RawByteString;
    function GetOutputUTFStrTest:RawByteString;

    property InputData : RawByteString read GetInputData;
    property InputDataVectors : ITestDataInputVectorContainer read GetInputVectors;
    property ExpectedOutput : RawByteString read GetOutputData;
    property ExpectedOutputUTFStrTest : RawByteString read GetOutputUTFStrTest;
  end;

  ITestDataRowSetup = interface
  ['{DCB0F980-7120-41A6-BD02-118B594E2AB6}']
    procedure SetExpectedOutput(const aValue:RawByteString);
    procedure SetExpectedOutputUTFStrTest(const aValue:RawByteString);

    property ExpectedOutput : RawByteString Write SetExpectedOutput;
    property ExpectedOutputUTFStrTest : RawByteString Write SetExpectedOutputUTFStrTest;

    procedure AddInputVector(const aData:RawByteString; const aRunCount:Cardinal=1;
                             const aConcatCount:Cardinal=1);
  end;

  ITestDataContainer = interface
  ['{65205874-94D9-424C-8314-4816D33CECA4}']
    function GetCount:Integer;
    property Count:Integer read GetCount;

    procedure Clear;
  end;

  // ---------------------------------------------------------------------------

  IHashTestDataRowSetup = interface(ITestDataRowSetup)
  ['{ADB4AFA2-4199-47F4-86F6-E84A20C3AA8E}']
    procedure SetRequiredDigestSize(const aValue:Integer);
    procedure SetPaddingByte(const aValue:Byte);

    property RequiredDigestSize : Integer Write SetRequiredDigestSize;
    property PaddingByte        : Byte Write SetPaddingByte;
  end;

  IHashTestDataRow = interface(ITestDataRow)
  ['{73ED2877-967A-410B-8493-636F099FBA60}']
    function GetRequiredDigestSize:Integer;
    function GetPaddingByte:Byte;

    property RequiredDigestSize : Integer read GetRequiredDigestSize;
    property PaddingByte        : Byte read GetPaddingByte;
  end;

  IHashTestDataContainer = interface(ITestDataContainer)
  ['{BDF2082D-3133-48D8-B9AA-87F3485FD91F}']
    function GetRows(aIndex:Integer):IHashTestDataRow;
    property Rows[aIndex:Integer]:IHashTestDataRow read GetRows;  default;

    function AddRow:IHashTestDataRowSetup;
  end;

function CreateTestDataContainer:ITestDataContainer;

implementation

uses
  Classes;

type
  TTestDataInputVector = class(TInterfacedObject, ITestDataInputVector)
  private
    FData     : RawByteString;
    FRunCount : Cardinal;
  protected // ITestDataInputVector
    function GetRunCount:Cardinal;
    function GetData:RawByteString;
  public
    constructor Create(const aData:RawByteString; const aRunCount:Cardinal);
  end;

  /// <summary>
  ///   All methods are protected by design so that nobody directly uses this class.
  ///   It shall be used via the ITestDataInputVectorContainer interface, which
  ///   automatically makes the methods allowed to be used externally public
  /// </summary>
  TTestDataInputVectorContainer = class(TInterfacedObject, ITestDataInputVectorContainer)
  private
    FVectors : TInterfaceList;
  protected // ITestDataInputVectorContainer
    function GetCount:Integer;
    function GetVectors(aIndex:Integer):ITestDataInputVector;
    /// <summary>
    ///   Adds an input vector for one test to the list
    /// </summary>
    /// <param name="aData">
    ///   Test data for the vector
    /// </param>
    /// <param name="aRunCount">
    ///   Number of times the test shall be repeated on the data given, default = 1
    /// </param>
    /// <param name="aConcatCount">
    ///   Number of times aData is being concatenated to form the real input data
    ///   for this test vector
    /// </param>
    /// <returns>
    ///   An interface to the generated test vector
    /// </returns>
    function AddInputVector(const aData:RawByteString; const aRunCount:Cardinal=1; const aConcatCount:Cardinal=1):ITestDataInputVector;
  public
    constructor Create;
    destructor Destroy; override;
  end;

  TTestDataRow = class(TInterfacedObject, ITestDataRow, ITestDataRowSetup, IHashTestDataRow, IHashTestDataRowSetup)
  private
    FInputData:RawByteString;
    FInputVectors:ITestDataInputVectorContainer;
    FOutputData:RawByteString;
    FOutputUTFStrTest:RawByteString;
    FReqDigSize:Integer;
    FPaddingByte:Byte;
  protected // ITestDataRow
    function GetInputData:RawByteString;
    function GetInputVectors:ITestDataInputVectorContainer;
    function GetOutputData:RawByteString;
    function GetOutputUTFStrTest:RawByteString;
  protected // ITestDataRowSetup
    procedure SetExpectedOutput(const aValue:RawByteString);
    procedure SetExpectedOutputUTFStrTest(const aValue:RawByteString);
    procedure AddInputVector(const aData:RawByteString; const aRunCount:Cardinal=1; const aConcatCount:Cardinal=1);
  protected // IHashTestDataRow
    function GetRequiredDigestSize:Integer;
    function GetPaddingByte:Byte;
  protected // IHashTestDataRowSetup
    procedure SetRequiredDigestSize(const aValue:Integer);
    procedure SetPaddingByte(const aValue:Byte);
  public
    constructor Create;
    destructor Destroy; override;
  end;

  TTestDataContainer = class(TInterfacedObject, ITestDataContainer, IHashTestDataContainer)
  private
    FDataRows:TInterfaceList;
  protected // ITestDataContainer
    function GetCount:Integer;
    function GetRows(aIndex:Integer):ITestDataRow;
    procedure Clear;
  protected // IHashTestDataContainer
    function HASH_AddRow:IHashTestDataRowSetup;                     function IHashTestDataContainer.AddRow = HASH_Addrow;
    function HASH_GetRows(aIndex:Integer):IHashTestDataRow;         function IHashTestDataContainer.GetRows = HASH_GetRows;
  public
    constructor Create;
    destructor Destroy; override;
  end;

function CreateTestDataContainer:ITestDataContainer;
begin
  result := TTestDataContainer.Create;
end;

{ TTestDataContainer }

procedure TTestDataContainer.Clear;
begin
  FDataRows.Clear;
end;

constructor TTestDataContainer.Create;
begin
  inherited Create;
  FDataRows := TInterfaceList.Create;
end;

destructor TTestDataContainer.Destroy;
begin
  FDataRows.Free;
  inherited;
end;

function TTestDataContainer.GetCount: Integer;
begin
  result := FDataRows.Count;
end;

function TTestDataContainer.GetRows(aIndex: Integer): ITestDataRow;
begin
  result := FDataRows.Items[aIndex] as ITestDataRow;
end;

function TTestDataContainer.HASH_AddRow: IHashTestDataRowSetup;
begin
  Result := TTestDataRow.Create;
  FDataRows.Add(Result);
end;

function TTestDataContainer.HASH_GetRows(aIndex: Integer): IHashTestDataRow;
begin
  result := FDataRows.Items[aIndex] as IHashTestDataRow;
end;

{ TTestDataRow }

procedure TTestDataRow.AddInputVector(const aData: RawByteString; const aRunCount, aConcatCount: Cardinal);
var
  lData:String;
  Idx:Integer;
  lVector:ITestDataInputVector;
begin
  lVector := FInputVectors.AddInputVector(aData, aRunCount, aConcatCount);

  lData := '';
  for Idx := 1 to lVector.RunCount do
  begin
    lData := lData + lVector.Data;
  end;

  FInputData := FInputData + lData;
end;

constructor TTestDataRow.Create;
begin
  inherited Create;
  FInputVectors := TTestDataInputVectorContainer.Create;
end;

destructor TTestDataRow.Destroy;
begin
  FInputVectors := NIL;
  inherited;
end;

function TTestDataRow.GetInputData: RawByteString;
begin
  result := FInputData;
end;

function TTestDataRow.GetInputVectors: ITestDataInputVectorContainer;
begin
  result := FInputVectors;
end;

function TTestDataRow.GetOutputData: RawByteString;
begin
  result := FOutputData;
end;

function TTestDataRow.GetOutputUTFStrTest: RawByteString;
begin
  result := FOutputUTFStrTest;
end;

function TTestDataRow.GetPaddingByte: Byte;
begin
  result := FPaddingByte;
end;

function TTestDataRow.GetRequiredDigestSize: Integer;
begin
  result := FReqDigSize;
end;

procedure TTestDataRow.SetExpectedOutput(const aValue: RawByteString);
begin
  FOutputData := aValue;
end;

procedure TTestDataRow.SetExpectedOutputUTFStrTest(const aValue: RawByteString);
begin
  FOutputUTFStrTest := aValue;
end;

procedure TTestDataRow.SetPaddingByte(const aValue: Byte);
begin
  FPaddingByte := aValue;
end;

procedure TTestDataRow.SetRequiredDigestSize(const aValue: Integer);
begin
  FReqDigSize := aValue;
end;

{ TTestDataInputVectorContainer }

function TTestDataInputVectorContainer.AddInputVector(const aData:RawByteString;
           const aRunCount:Cardinal=1; const aConcatCount:Cardinal=1):ITestDataInputVector;
var
  lData : RawByteString;
  Idx   : Integer;
begin
  lData := '';
  for Idx := 1 to aConcatCount do
  begin
    lData := lData + aData;
  end;
  Result := TTestDataInputVector.Create(lData, aRunCount);
  FVectors.Add(Result);
end;

constructor TTestDataInputVectorContainer.Create;
begin
  inherited Create;
  FVectors := TInterfaceList.Create;
end;

destructor TTestDataInputVectorContainer.Destroy;
begin
  FVectors.Free;
  inherited;
end;

function TTestDataInputVectorContainer.GetCount: Integer;
begin
  result := FVectors.Count;
end;

function TTestDataInputVectorContainer.GetVectors(aIndex: Integer): ITestDataInputVector;
begin
  result := FVectors.Items[aIndex] as ITestDataInputVector;
end;

{ TTestDataInputVector }

constructor TTestDataInputVector.Create(const aData: RawByteString; const aRunCount: Cardinal);
begin
  inherited Create;
  FData     := aData;
  FRunCount := aRunCount;
end;

function TTestDataInputVector.GetData: RawByteString;
begin
  result := FData;
end;

function TTestDataInputVector.GetRunCount: Cardinal;
begin
  result := FRunCount;
end;

end.
