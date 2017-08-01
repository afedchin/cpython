#include "Python.h"

#if defined(MS_UWP) || defined(TARGET_WINDOWS_STORE)

#include <SDKDDKVer.h>
#include <windows.h>
#include <ppltasks.h>
#include <string>
#include <locale>
#include <codecvt>
#include <map>

#define X509_ASN_ENC "x509_asn"

using namespace concurrency;
using namespace Platform;
using namespace Windows::ApplicationModel;
using namespace Windows::System::UserProfile;
using namespace Windows::Storage;
using namespace Windows::Storage::Streams;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Certificates;
using namespace Windows::Foundation;

std::wstring win32ConvertUtf8ToW(const std::string &text, bool *resultSuccessful /* = NULL*/)
{
  if (text.empty())
  {
    if (resultSuccessful != NULL)
      *resultSuccessful = true;
    return L"";
  }
  if (resultSuccessful != NULL)
    *resultSuccessful = false;

  int bufSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), -1, NULL, 0);
  if (bufSize == 0)
    return L"";
  wchar_t *converted = new wchar_t[bufSize];
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), -1, converted, bufSize) != bufSize)
  {
    delete[] converted;
    return L"";
  }

  std::wstring Wret(converted);
  delete[] converted;

  if (resultSuccessful != NULL)
    *resultSuccessful = true;
  return Wret;
}

std::string win32ConvertWToUtf8(const std::wstring &text, bool *resultSuccessful /*= NULL*/)
{
  if (text.empty())
  {
    if (resultSuccessful != NULL)
      *resultSuccessful = true;
    return "";
  }
  if (resultSuccessful != NULL)
    *resultSuccessful = false;

  int bufSize = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(), -1, NULL, 0, NULL, NULL);
  if (bufSize == 0)
    return "";
  char * converted = new char[bufSize];
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.c_str(), -1, converted, bufSize, NULL, NULL) != bufSize)
  {
    delete[] converted;
    return "";
  }

  std::string ret(converted);
  delete[] converted;

  if (resultSuccessful != NULL)
    *resultSuccessful = true;
  return ret;
}

extern "C" {
    
void win32_urandom(unsigned char *buffer, Py_ssize_t size, int raise)
{
    IBuffer^ data = CryptographicBuffer::GenerateRandom(size);
    Array<unsigned char>^ data2;
    CryptographicBuffer::CopyToByteArray(data, &data2);
    for(int i=0; i < size; i++)
        buffer[i] = data2[i];
}

/*BOOL*/ int uwp_startfile(const wchar_t *operation, const wchar_t *path)
{
    /* TODO: Implement launcher */
    return FALSE;
}

size_t uwp_Utf8ToW(const char* src, wchar_t* buffer, int maxlen)
{
  bool success;
  std::wstring converted = win32ConvertUtf8ToW(std::string(src), &success);
  if (!success)
    return 0;

  int len = min(converted.length(), maxlen - 1);
  wcsncpy(buffer, converted.c_str(), len);
  buffer[len] = '\0';

  return len;
}

size_t uwp_getinstallpath(wchar_t *buffer, size_t cch)
{
    try
    {
        String^ path = Package::Current->InstalledLocation->Path;
        wcscpy_s(buffer, cch, path->Data());
        return path->Length();
    }
    catch (Exception^)
    {
        return 0;
    }
}

static bool set_item(PyObject *d, const wchar_t *name, String^ (*value_func)())
{
    PyObject *valueobj;
    try
    {
        auto value = value_func();
        valueobj = PyUnicode_FromWideChar(value->Data(), -1);
    }
    catch (Exception^)
    {
        valueobj = PyUnicode_FromString("");
    }
    
    if (!valueobj)
        return false;

    auto nameobj = PyUnicode_FromWideChar(name, -1);
    if (!nameobj)
    {
        Py_DECREF(valueobj);
        return false;
    }

    bool success = PyDict_SetItem(d, nameobj, valueobj) == 0;
    Py_DECREF(nameobj);
    Py_DECREF(valueobj);
    return success;
}

PyObject * uwp_defaultenviron()
{
    auto d = PyDict_New();

    if (d != nullptr &&
        set_item(d, L"INSTALLPATH", [] { return Package::Current->InstalledLocation->Path; }) &&
        set_item(d, L"APPDATA", [] { return ApplicationData::Current->RoamingFolder->Path; }) &&
        set_item(d, L"LOCALAPPDATA", [] { return ApplicationData::Current->LocalFolder->Path; }) &&
        set_item(d, L"TEMP", [] { return ApplicationData::Current->TemporaryFolder->Path; }) &&
        set_item(d, L"TMP", [] { return ApplicationData::Current->TemporaryFolder->Path; }) &&
        set_item(d, L"PATH", [] { return ref new String(); })
        )
        return d;

    Py_DECREF(d);
    return nullptr;
}

char* win10_getenv(const char* n)
{
  static std::map<std::string, std::string> sEnvironment;
  bool success;

  if (n == nullptr)
    return nullptr;

  std::string name(n);

  // check key
  if (!name.empty())
  {
    std::wstring Wname(win32ConvertUtf8ToW(name, &success));
    if (success)
    {
      Platform::String^ key = ref new Platform::String(Wname.c_str());

      ApplicationDataContainer^ localSettings = ApplicationData::Current->LocalSettings;
      auto values = localSettings->Values;

      if (values->HasKey(key))
      {
        auto value = safe_cast<Platform::String^>(values->Lookup(key));
        std::string result = win32ConvertWToUtf8(std::wstring(value->Data()), &success);
        if (success)
        {
          sEnvironment[name] = result;
          return (char*)(sEnvironment[name].c_str());
        }
      }
    }
  }
  return nullptr;
}

#if 0
    PyObject * uwp_enumcertificates(const char *store_name)
    {
        PyObject *result = NULL;
        PyObject *keyusage = NULL, *cert = NULL, *enc = NULL, *tup = NULL;
        
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        auto wStoreName = ref new Platform::String(converter.from_bytes(std::string(store_name)).c_str());

        if (wStoreName->IsEmpty())
        {
            // Empty string return invalid args.
            return PyErr_SetFromWindowsErr(ERROR_INVALID_PARAMETER);
        }

        auto certQuery = ref new CertificateQuery();
        certQuery->StoreName = wStoreName;
        auto certs = concurrency::create_task(CertificateStores::FindAllAsync(certQuery)).get();
        
        result = PyList_New(0);
        if (result == NULL)
        {
            return result;
        }

        for (auto itr = certs->First(); itr->HasCurrent; itr->MoveNext())
        {
            auto certificate = itr->Current;
            auto encodedCert = certificate->GetCertificateBlob();

            byte* buffer = reinterpret_cast<byte*>(PyMem_Malloc(encodedCert->Length));
            if (!buffer) {
                Py_CLEAR(result);
                result = NULL;
                break;
            }

            auto bufferArray = ArrayReference<byte>(buffer, encodedCert->Length);

            auto reader = DataReader::FromBuffer(encodedCert);

            reader->ReadBytes(bufferArray);

            cert = PyBytes_FromStringAndSize((const char *)buffer, encodedCert->Length);
            PyMem_Free(buffer);
            buffer = NULL;

            if (!cert) {
                Py_CLEAR(result);
                result = NULL;
                break;
            }

            keyusage = PySet_New(NULL);
            for (auto kuitr = certificate->EnhancedKeyUsages->First(); kuitr->HasCurrent; kuitr->MoveNext())
            {
                PySet_Add(keyusage, PyUnicode_FromWideChar(kuitr->Current->Data(), kuitr->Current->Length()));
            }

            enc = PyUnicode_InternFromString(X509_ASN_ENC);
            if ((tup = PyTuple_New(3)) == NULL) {
                Py_CLEAR(result);
                break;
            }

            PyTuple_SET_ITEM(tup, 0, cert);

            PyTuple_SET_ITEM(tup, 1, enc);

            PyTuple_SET_ITEM(tup, 2, keyusage);

            PyList_Append(result, tup);

            cert = NULL;
            enc = NULL;
            keyusage = NULL;
        }

        return result;
    }
#endif
}

#endif
