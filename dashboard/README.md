# Certificate Radar Dashboard

A Vite + React + TypeScript dashboard for the Certificate Radar API. UI components are built with Mantine and the visual language uses a dark navy / cyan security-console palette.

## Features

- Certificate overview with target count and status statistics.
- Latest scan table with frontend filtering and sorting.
- Owner search, issuer filter, status/risk filters and configurable expiration range.
- Client-side sorting by owner, server name, issuer, expiration, days left, status and risk score.
- Detail drawer for certificate, TLS, validation, names, risk and findings.
- Risk findings are shown at the end of the detail model for elevated risk levels.
- Add target -> automatic first scan.
- Edit target metadata and prepared address-change payload.
- Delete target confirmation modal with a documented backend placeholder.
- Manual scan without confirmation.
- Automatic refresh every 20 seconds while preserving UI state.
- English frontend error notifications with bounded error detail.
- Responsive desktop/laptop/mobile layout; mobile table hides secondary columns.
- Dockerfile and docker-compose configuration.

## Run locally

```bash
cp .env.example .env
npm install
npm run dev
```

`VITE_API_BASE_URL` points the browser at the Certificate Radar API. Example:

```env
VITE_API_BASE_URL=http://localhost:8080
```

## Build

```bash
npm run build
npm run preview
```

## Docker

Set `VITE_API_BASE_URL` before building because Vite embeds `VITE_*` variables into the static bundle:

```bash
VITE_API_BASE_URL=http://localhost:8080 docker compose up --build
```

Dashboard is available on `http://localhost:3000`.

## Backend contract notes

The supplied MVP API documents `PUT /api/targets/:id` as accepting only `owner`, `criticality` and `enabled`. The dashboard UI nevertheless includes target address editing because this was requested for the final interface. The API client sends the parsed address/port/server name as part of the update request; the backend must be extended to accept those fields before that part of the UI can persist an address change.

The delete action is intentionally a no-op placeholder. Replace the marked TODO in `src/components/TargetDeleteModal.tsx` with the future delete API call.

The dashboard intentionally does not reproduce the Risk Engine formula. Elevated-risk explanations use only API `findings`.
