import ollama
import json
import re
import os

def classify_iot_cve_with_llm_locally(
        cve_id: str,
        description: str,
        date_published: str,
        model_name: str,
        affected_items: list = None,
        provider_short_name: str = None,
        tags: list = None
) -> dict | None: # Updated return type to include None
    VALID_SIGNIFICANT_FIELDS = [
        "description",
        "date_published",
        "affected_items",
        "provider_short_name",
        "tags"
    ]

    allowed_fields_str = ', '.join([f'"{field}"' for field in VALID_SIGNIFICANT_FIELDS])

    system_prompt = (
        "You are a strict JSON-generating assistant that determines whether a CVE (Common Vulnerabilities and Exposures) is IoT-related based on our definition. "
        "After classifying, you must also identify the *single most significant field* that led to your decision from the provided options.\n\n"

        "We define an IoT system as comprising three primary components: device, network, and application. "
        "The device component refers to physical objects embedded with sensors, software, and connectivity features that allow it to collect, exchange, and act on data over the internet or other networks without requiring direct human intervention. "
        "Examples include—but are not limited to—routers, switches, IP cameras, smart home devices, etc. "
        "Moreover, components that enable IoT connectivity, such as embedded modules, smart controllers, and network interfaces—are considered part of the IoT devices. "
        "The network component serves as the communication layer that facilitates data transfer and connectivity between devices. "
        "This includes, but is not limited to, technologies and protocols such as BLE, CoAP, MQTT. "
        "The application component is responsible for processing data into actionable insights and delivering user-facing functionality. "
        "Examples include companion mobile apps, user interfaces, and platforms like IFTTT and SmartThings.\n"
        "Given the above definition of IoT system, we define an IoT-related CVE as one that impacts or targets essential components of an IoT system, including devices, networks, and applications and is primarily or exclusively deployed within IoT contexts. "
        "It is worth noting that we did not consider the smartphone, computer, or tablet as IoT device.\n"

        "You must return a strict JSON response in the exact format:\n"
        "{\n"
        "  \"is_iot\": true or false,\n"
        f"  \"most_significant_field\": \"[one of: {allowed_fields_str}]\"\n"
        "}\n"
        "Do not include any explanation, think, comments, explanations, or text outside the JSON object.\n"
    )

    user_prompt_parts = [
        'Classify this CVE as IoT-related or not based on the definition provided. Also, identify the single most significant field for your decision from the options: ' + ', '.join(
            VALID_SIGNIFICANT_FIELDS) + '.'
    ]

    user_prompt_parts.append(f'CVE ID: {cve_id if cve_id else "N/A"}')
    user_prompt_parts.append(f'Description: {description if description else "N/A"}')
    user_prompt_parts.append(f'Date Published: {date_published if date_published else "N/A"}')

    if affected_items:
        affected_str_parts = []
        for item in affected_items:
            vendor = item.get('vendor', 'Unknown Vendor')
            product = item.get('product', 'Unknown Product')
            affected_str_parts.append(f"{vendor} {product}".strip())
        affected_str = "; ".join(affected_str_parts)
        user_prompt_parts.append(f'Affected Items: {affected_str}')
    else:
        user_prompt_parts.append('Affected Items: N/A')

    user_prompt_parts.append(f'Provider: {provider_short_name if provider_short_name else "N/A"}')

    if tags:
        user_prompt_parts.append(f'Tags: {", ".join(tags)}')
    else:
        user_prompt_parts.append('Tags: N/A')

    user_prompt = "\n".join(user_prompt_parts)

    try:
        response = ollama.chat(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            options={'temperature': 0.0}
        )

        raw = response["message"]["content"].strip()
        allowed_fields_regex_str = '|'.join(re.escape(field) for field in VALID_SIGNIFICANT_FIELDS)

        match = re.search(
            r'{\s*"is_iot"\s*:\s*(true|false)\s*,\s*'
            r'"most_significant_field"\s*:\s*"'
            f'({allowed_fields_regex_str})"'
            r'\s*}',
            raw
        )

        if match:
            try:
                matched_json_str = match.group(0)
                parsed_json = json.loads(matched_json_str)

                # Ensure both keys are present and valid
                is_iot_val = parsed_json.get("is_iot")
                msf_val = parsed_json.get("most_significant_field")

                if isinstance(is_iot_val, bool) and msf_val in VALID_SIGNIFICANT_FIELDS:
                    return {
                        "is_iot": is_iot_val,
                        "most_significant_field": msf_val
                    }
                else:
                    print(f"❗ Invalid 'is_iot' type or 'most_significant_field' value for {cve_id}: {parsed_json}")
                    return None # Return None if parsed JSON is semantically invalid
            except json.JSONDecodeError as e:
                print(f"❗ Failed to parse valid JSON from regex match for {cve_id}: {e} - Raw match: {match.group(0)}")
                return None # Return None on JSON parsing error
        else:
            print(f"⚠️ No complete valid JSON (is_iot & most_significant_field) found for {cve_id}: {raw[:200]}...")
            return None # Return None if no valid JSON structure is found

    except Exception as e:
        print(f"⚠️ LLM IoT classification failed for {cve_id}: {e}")
        return None # Return None on any general exception