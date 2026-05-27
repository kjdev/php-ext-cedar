/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: c0a768b1135221393bb19d04c3001606665fb33e */

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Cedar_PolicyStore___construct, 0, 0, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, policyStoreId, IS_STRING, 1, "null")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Cedar_PolicyStore_loadFile, 0, 2, IS_STATIC, 0)
	ZEND_ARG_TYPE_INFO(0, policyId, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, path, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Cedar_PolicyStore_loadString, 0, 2, IS_STATIC, 0)
	ZEND_ARG_TYPE_INFO(0, policyId, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, cedarText, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Cedar_PolicyStore_id, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Cedar_PolicyStore_policyIds, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_class_Cedar_AuthorizationClient___construct, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, policyStore, Cedar\\PolicyStore, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_class_Cedar_AuthorizationClient_isAuthorized, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, params, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

#define arginfo_class_Cedar_AuthorizationClient_isAuthorizedWithToken arginfo_class_Cedar_AuthorizationClient_isAuthorized

ZEND_METHOD(Cedar_PolicyStore, __construct);
ZEND_METHOD(Cedar_PolicyStore, loadFile);
ZEND_METHOD(Cedar_PolicyStore, loadString);
ZEND_METHOD(Cedar_PolicyStore, id);
ZEND_METHOD(Cedar_PolicyStore, policyIds);
ZEND_METHOD(Cedar_AuthorizationClient, __construct);
ZEND_METHOD(Cedar_AuthorizationClient, isAuthorized);
ZEND_METHOD(Cedar_AuthorizationClient, isAuthorizedWithToken);

static const zend_function_entry class_Cedar_PolicyStore_methods[] = {
	ZEND_ME(Cedar_PolicyStore, __construct, arginfo_class_Cedar_PolicyStore___construct, ZEND_ACC_PUBLIC)
	ZEND_ME(Cedar_PolicyStore, loadFile, arginfo_class_Cedar_PolicyStore_loadFile, ZEND_ACC_PUBLIC)
	ZEND_ME(Cedar_PolicyStore, loadString, arginfo_class_Cedar_PolicyStore_loadString, ZEND_ACC_PUBLIC)
	ZEND_ME(Cedar_PolicyStore, id, arginfo_class_Cedar_PolicyStore_id, ZEND_ACC_PUBLIC)
	ZEND_ME(Cedar_PolicyStore, policyIds, arginfo_class_Cedar_PolicyStore_policyIds, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static const zend_function_entry class_Cedar_AuthorizationClient_methods[] = {
	ZEND_ME(Cedar_AuthorizationClient, __construct, arginfo_class_Cedar_AuthorizationClient___construct, ZEND_ACC_PUBLIC)
	ZEND_ME(Cedar_AuthorizationClient, isAuthorized, arginfo_class_Cedar_AuthorizationClient_isAuthorized, ZEND_ACC_PUBLIC)
	ZEND_ME(Cedar_AuthorizationClient, isAuthorizedWithToken, arginfo_class_Cedar_AuthorizationClient_isAuthorizedWithToken, ZEND_ACC_PUBLIC)
	ZEND_FE_END
};

static zend_class_entry *register_class_Cedar_PolicyStore(void)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Cedar", "PolicyStore", class_Cedar_PolicyStore_methods);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL);
#else
	class_entry = zend_register_internal_class_ex(&ce, NULL);
	class_entry->ce_flags |= ZEND_ACC_FINAL;
#endif

	return class_entry;
}

static zend_class_entry *register_class_Cedar_AuthorizationClient(void)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Cedar", "AuthorizationClient", class_Cedar_AuthorizationClient_methods);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, NULL, ZEND_ACC_FINAL);
#else
	class_entry = zend_register_internal_class_ex(&ce, NULL);
	class_entry->ce_flags |= ZEND_ACC_FINAL;
#endif

	return class_entry;
}

static zend_class_entry *register_class_Cedar_Exception_PolicyParseException(zend_class_entry *class_entry_RuntimeException)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Cedar\\Exception", "PolicyParseException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_RuntimeException, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_RuntimeException);
#endif

	return class_entry;
}

static zend_class_entry *register_class_Cedar_Exception_EvaluationException(zend_class_entry *class_entry_RuntimeException)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Cedar\\Exception", "EvaluationException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_RuntimeException, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_RuntimeException);
#endif

	return class_entry;
}

static zend_class_entry *register_class_Cedar_Exception_ResourceNotFoundException(zend_class_entry *class_entry_RuntimeException)
{
	zend_class_entry ce, *class_entry;

	INIT_NS_CLASS_ENTRY(ce, "Cedar\\Exception", "ResourceNotFoundException", NULL);
#if (PHP_VERSION_ID >= 80400)
	class_entry = zend_register_internal_class_with_flags(&ce, class_entry_RuntimeException, 0);
#else
	class_entry = zend_register_internal_class_ex(&ce, class_entry_RuntimeException);
#endif

	return class_entry;
}
