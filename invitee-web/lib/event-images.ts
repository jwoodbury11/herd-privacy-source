export const EVENT_IMAGE_IDS = [
  "poker",
  "tennis",
  "board-games",
  "house-drinks",
  "restaurant",
  "cocktail-bar",
  "club-dancing",
  "movie-night",
  "park-picnic",
  "travel-airport",
  "camping",
  "fishing",
  "birthday-party",
  "jacuzzi",
  "skiing",
  "other",
] as const;

export type EventImageID = (typeof EVENT_IMAGE_IDS)[number];

export const DEFAULT_EVENT_IMAGE_ID: EventImageID = "poker";

export function eventImagePath(id: EventImageID | null | undefined): string {
  return `/event-images/${id ?? DEFAULT_EVENT_IMAGE_ID}.png`;
}
