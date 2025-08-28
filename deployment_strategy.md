# Deployment Strategy — Project Guardian 2.0 (Vidit Pokhral)

## Introduction

Flixkart recently completed a security audit, which discovered a high-risk vulnerability regarding unmonitored assets and external API integrations exposing personally identifiable information (PII) with fraud incidents resulting. Our task is to deploy a PII Detector & Redactor to detect and redact sensitive information, such as phone numbers or address identifiers, which must balance being low-latency and scalable while supporting a large eCommerce platform. The approach must also be scalable, cost-effective, and easy-to-implement.

## Proposed Deployment Methodology

I recommend implementing the solution as an **API Gateway plugin**. Positioned between the frontend and backend, this layer can intercept all data traffic, including external API streams, to prevent PII from reaching internal systems or logs where leaks were detected.

### Rationale

- **Effectiveness**: The gateway will access every data point and allow visibility into possible weaknesses in an endpoint or API logs the end-user could never reach.
- **Scalability**: The gateway handles very high traffic, with horizontal scaling and load balancers that Flixkart can implement as needed.
- **Latency**: The gateway only has to make a check once per request, effectively lowering our latency by having the check performed by a Python script with little overhead.
- **Cost-Effectiveness**: Since the gateway is already leveraged within the architecture, it will not require anyone to purchase any additional hardware, or make major changes to the application.
- **Integration**: The gateway is already leveraged in the architecture in many forms, and modern gateways (e.g., Kong or Apigee) allow for custom plugins to be added to allow seamless adoption without interrupting any existing integrations.

## Implementation Plan

- **Set-up**: Detector_full_candidate_name.py will be set-up as a plugin to run within the API Gateways passing JSON data in real-time to it.
- **Scope**: The detector will be executed only on the endpoints, `/api/analyze` and `/api/analyze_stream`, where the PII Leak has leaked PII fields. The detector will redact fields that are sensitive, and will add an `is_pii` flag within the fields representing each `patient`.
- **Monitoring**: The gateway logs will be monitored regularly to ensure there are no moments of PII escaping the api, and an alert will set-up for any alerts to public PII that could be of concern. Other Considerations

## Additional Considerations

- **Redundancy**: The Python script could be pulled into a Sidecar container that would run beside the respective critical services (e.g. Backend + MCP), so if the gateway fails, the Sidecar container would act as a fall back, and cost only slightly more.
- **Testing Phase**: Once we deploy the gateway plugin in a staging environment. The testing will review latency and accuracy; we want to minimize latency to under 50ms, and at best, a F1-score of ≥ 0.85.
- **Maintenance**: PII detection rules will be updated via a centralized config file and issued to the plugin on request.

## Conclusion

Deploying the PII solution as an API Gateway plugin is a viable, scalable and secure way to minimize Flixkart's risk of data leaks. This helps strike a balance between performance and practicality, protecting customer data and reducing the potential for fraud.
