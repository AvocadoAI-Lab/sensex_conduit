# Quicktype 參數說明文件

## 安裝說明

在專案中安裝 quicktype：
```bash
npm install quicktype
```

使用 npx 執行（推薦方式）：
```bash
npx quicktype [參數]
```

或者在 package.json 的 scripts 中加入：
```json
{
  "scripts": {
    "generate-types": "quicktype **/*.json -o types.ts"
  }
}
```

然後使用：
```bash
npm run generate-types
```

## 基本參數

- `-o, --out FILE`：指定輸出檔案
- `-s, --src-lang LANG`：指定輸入的語言（預設：json）
- `-t, --lang LANG`：指定輸出的語言（預設：typescript）

## 輸入相關參數

- `--src FILE|URL`：從檔案或 URL 讀取
- `--src-urls FILE`：從含有 URL 列表的檔案讀取
- `--no-maps`：不要生成源碼映射
- `--alphabetize-properties`：將屬性按字母順序排序

## 類型相關參數

- `--no-enums`：不生成列舉類型，改用字串
- `--just-types`：僅輸出類型定義
- `--explicit-unions`：明確定義聯合類型
- `--all-properties-optional`：將所有屬性設為可選
- `--no-date-times`：不要使用 Date 類型
- `--prefer-unions`：偏好使用聯合類型而非列舉

## 命名相關參數

- `--top-level NAME`：指定頂層類型名稱
- `--acronym-style none|original|pascal|camel|lowerCase`：設定縮寫詞風格
- `--naming-style pascal|underscore|camel|upper|pascal|camel|upper|underscore`：命名風格

## 程式碼風格參數

- `--indentation 2|4|8|tab`：設定縮排
- `--no-comments`：不生成註解
- `--quiet`：減少輸出訊息
- `--debug`：輸出除錯訊息

## 常用組合範例

### 1. 基本使用
```bash
npx quicktype input.json -o types.ts
```

### 2. 最簡潔輸出
```bash
npx quicktype input.json -o types.ts --just-types --no-enums
```

### 3. 完整類型定義
```bash
npx quicktype input.json -o types.ts --alphabetize-properties --explicit-unions
```

### 4. 自訂命名風格
```bash
npx quicktype input.json -o types.ts --naming-style pascal --acronym-style pascal
```

### 5. 所有屬性可選
```bash
npx quicktype input.json -o types.ts --all-properties-optional
```

## 進階使用技巧

1. 處理多個輸入檔案：
```bash
npx quicktype **/*.json -o types.ts
```

2. 從 URL 生成類型：
```bash
npx quicktype --src https://api.example.com/schema.json -o types.ts
```

3. 自訂縮排和格式：
```bash
npx quicktype input.json -o types.ts --indentation 2 --no-comments
```

## 注意事項

- 使用 `--just-types` 可以產生最乾淨的輸出
- `--no-enums` 適合當你想要更好的型別推斷時使用
- `--alphabetize-properties` 有助於維護程式碼的一致性
- 使用 `--explicit-unions` 可以獲得更精確的型別定義

## 預定義命令

### 1. 基本型別生成
```bash
quicktype **/*.json -o types1.ts
```
- 處理所有 JSON 檔案
- 包含完整的型別定義和列舉
- 適合需要完整型別資訊的情況

### 2. 無列舉型別生成
```bash
quicktype **/*.json -o types2.ts --no-enums
```
- 處理所有 JSON 檔案
- 不生成列舉，改用字串字面值
- 適合需要更簡單型別結構的情況

### 3. 最小化型別生成
```bash
quicktype **/*.json -o types3.ts --no-enums --just-types --alphabetize-properties
```
- 處理所有 JSON 檔案
- 不生成列舉
- 僅生成型別定義
- 屬性按字母順序排序
- 產生最簡潔且易於維護的型別定義
