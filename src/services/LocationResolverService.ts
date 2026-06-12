/**
 * Resolves latitude/longitude coordinates to a human-readable location label.
 * Uses OpenStreetMap Nominatim reverse geocoding (https://nominatim.org).
 */
import { config } from '../config/env';
import { ValidationError } from '../types';

interface NominatimAddress {
   city?: string;
   town?: string;
   village?: string;
   state?: string;
   country?: string;
}

interface NominatimReverseResponse {
   display_name?: string;
   address?: NominatimAddress;
}

export class LocationResolverService {
   private readonly baseUrl: string;
   private readonly userAgent: string;

   constructor(
      baseUrl: string = config.NOMINATIM_BASE_URL,
      userAgent: string = config.NOMINATIM_USER_AGENT,
   ) {
      this.baseUrl = baseUrl.replace(/\/$/, '');
      this.userAgent = userAgent;
   }

   async resolveFromCoordinates(latitude: number, longitude: number): Promise<string> {
      try {
         const url = new URL(`${this.baseUrl}/reverse`);
         url.searchParams.set('lat', String(latitude));
         url.searchParams.set('lon', String(longitude));
         url.searchParams.set('format', 'json');

         const response = await fetch(url, {
            headers: {
               'User-Agent': this.userAgent,
               Accept: 'application/json',
            },
            signal: AbortSignal.timeout(10_000),
         });

         if (!response.ok) {
            throw new ValidationError('Unable to resolve location from coordinates');
         }

         const data = (await response.json()) as NominatimReverseResponse;
         const location = this.formatLocation(data);
         if (!location) {
            throw new ValidationError('Unable to resolve location from coordinates');
         }

         return location;
      } catch (error) {
         if (error instanceof ValidationError) {
            throw error;
         }
         throw new ValidationError('Unable to resolve location from coordinates');
      }
   }

   private formatLocation(data: NominatimReverseResponse): string | null {
      const address = data.address;
      if (address) {
         const locality = address.city ?? address.town ?? address.village;
         const parts = [locality, address.state, address.country].filter(
            (part): part is string => Boolean(part && part.trim()),
         );
         if (parts.length > 0) {
            return parts.join(', ').slice(0, 200);
         }
      }

      const displayName = data.display_name?.trim();
      if (displayName) {
         return displayName.slice(0, 200);
      }

      return null;
   }
}
