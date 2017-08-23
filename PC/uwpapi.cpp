#include "Python.h"

#ifdef TARGET_WINDOWS_STORE

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
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Networking;
using namespace Windows::Networking::Connectivity;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Certificates;
using namespace Windows::Storage;
using namespace Windows::Storage::Streams;
using namespace Windows::System::UserProfile;

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

void win10_getversion(PyObject* version)
{
	int pos = 0;

	// get the system version number
	auto sv = Windows::System::Profile::AnalyticsInfo::VersionInfo->DeviceFamilyVersion;
	wchar_t* end;
	unsigned long long v = wcstoull(sv->Data(), &end, 10);
	unsigned long long major = (v & 0xFFFF000000000000L) >> 48;
	unsigned long long minor = (v & 0x0000FFFF00000000L) >> 32;
	unsigned long long build = (v & 0x00000000FFFF0000L) >> 16;

	PyStructSequence_SET_ITEM(version, pos++, PyLong_FromLong(major));
	PyStructSequence_SET_ITEM(version, pos++, PyLong_FromLong(minor));
	PyStructSequence_SET_ITEM(version, pos++, PyLong_FromLong(build));
	PyStructSequence_SET_ITEM(version, pos++, PyLong_FromLong(VER_PLATFORM_WIN32_NT));
	PyStructSequence_SET_ITEM(version, pos++, PyUnicode_FromString(""));
	PyStructSequence_SET_ITEM(version, pos++, PyLong_FromLong(0)); // TODO
	PyStructSequence_SET_ITEM(version, pos++, PyLong_FromLong(0)); // TODO
	PyStructSequence_SET_ITEM(version, pos++, PyLong_FromLong(0)); // TODO
	PyStructSequence_SET_ITEM(version, pos++, PyLong_FromLong(1)); // TODO

}

static std::map<std::wstring, std::wstring> sEnvironment;

void win10_convertenviron(PyObject *d)
{
    ApplicationDataContainer^ localSettings = ApplicationData::Current->LocalSettings;
    auto values = localSettings->Values;
	auto iterator = values->First();
	if (iterator->HasCurrent)
	{
		do
		{
			PyObject *k;
			PyObject *v;
			auto current = iterator->Current;
			if (current->Key == nullptr || current->Key->Length() == 0)
				continue;

			k = PyUnicode_FromWideChar(current->Key->Data(), (Py_ssize_t)(current->Key->Length()));
			if (k == NULL) {
				PyErr_Clear();
				continue;
			}

			auto val = current->Value;
			Platform::String^ valStr = "";
			if (val != nullptr)
				valStr = val->ToString();
			
			v = PyUnicode_FromWideChar(valStr->Data(), valStr->Length());
			if (v == NULL) {
				PyErr_Clear();
				Py_DECREF(k);
				continue;
			}
			if (PyDict_GetItem(d, k) == NULL) {
				if (PyDict_SetItem(d, k, v) != 0)
					PyErr_Clear();
			}
			Py_DECREF(k);
			Py_DECREF(v);

			std::wstring key(current->Key->Data());
			std::wstring value(current->Value->ToString()->Data());
			sEnvironment[key] = value;

		} while (iterator->MoveNext());
	}
}

wchar_t* win10_wgetenv(const wchar_t* n)
{
    if (n == nullptr)
        return nullptr;

    std::wstring name(n);

    // check key
    if (!name.empty())
    {
        Platform::String^ key = ref new Platform::String(name.c_str());

        ApplicationDataContainer^ localSettings = ApplicationData::Current->LocalSettings;
        auto values = localSettings->Values;

        if (values->HasKey(key))
        {
            auto value = safe_cast<Platform::String^>(values->Lookup(key));
            std::wstring result(value->Data());
            sEnvironment[name] = result;
            return const_cast<wchar_t*>(sEnvironment[name].c_str());
        }
    }
    return nullptr;
}

char* win10_getenv(const char* n)
{
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
        wchar_t* wvalue = win10_wgetenv(Wname.c_str());
        if (wvalue)
        {
            std::string result = win32ConvertWToUtf8(std::wstring(wvalue), &success);
            if (success)
            {
                return const_cast<char*>(result.c_str());
            }
        }
    }
  }
  return nullptr;
}

int win10_wsetenv(const wchar_t *name, const wchar_t* value, int action = 0)
{
	int retValue = 0;
	ApplicationDataContainer^ localSettings = ApplicationData::Current->LocalSettings;
	auto values = localSettings->Values;

	Platform::String^ key = ref new Platform::String(name);
	Platform::String^ val = ref new Platform::String(value);

	switch (action)
	{
	case 1: // delete
		if (values->HasKey(key))
		{
			values->Remove(key);
		}
		retValue = 0;
		break;

	default:
		retValue = values->Insert(key, val) ? 0 : 4;
		break;
	}
	return retValue;
}

int win10_wunsetenv(const wchar_t* name)
{
	return win10_wsetenv(name, L"", 1);
}

int win10_wputenv(const wchar_t *env)
{
	std::wstring envstring(env);

	if (envstring.empty())
		return 0;
	size_t pos = envstring.find('=');
	if (pos == 0) // '=' is the first character
		return -1;
	if (pos == std::wstring::npos)
		return win10_wunsetenv(envstring.c_str());
	if (pos == envstring.length() - 1) // '=' is in last position
	{
		std::wstring name(envstring);
		name.erase(name.length() - 1, 1);
		return win10_wunsetenv(name.c_str());
	}
	std::wstring name(envstring, 0, pos), value(envstring, pos + 1);

	return win10_wsetenv(name.c_str(), value.c_str());
}

/* try to implement behavior of GetComputerNameExW */
int win10_gethostname(wchar_t *buf, unsigned long *size)
{
    IIterator<HostName^>^ iterator = nullptr;

    auto hostNames = NetworkInformation::GetHostNames();
    if (hostNames == nullptr || hostNames->Size == 0)
        goto fail;

    iterator = hostNames->First();
    do
    {
        auto hostName = iterator->Current;
        if (hostName->Type != HostNameType::DomainName)
            continue;

        unsigned long sized = 0;
        if (size)
        {
            sized = *size;
            *size = hostName->DisplayName->Length();
        }

        if (hostName->DisplayName->Length() == 0 || hostName->DisplayName->Length() > sized)
            return 0;

        wcscpy(buf, hostName->DisplayName->Data());
        return 1;
    } 
    while (iterator->MoveNext());

fail:
    if (size)
        size = 0;
    return 0;
}
}

#endif
