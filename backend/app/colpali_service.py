import base64
import io
from datetime import datetime
from PIL import Image
from pathlib import Path
from typing import List, Dict, Optional
import json
from byaldi import RAGMultiModalModel


class ModelCache:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self._model = None
        self._last_used: Optional[datetime] = None

    def get(self):
        if self._model is None or self._last_used is None:
            return None
        if (datetime.utcnow() - self._last_used).total_seconds() > self.ttl_seconds:
            self.clear()
            return None
        self._last_used = datetime.utcnow()
        return self._model

    def set(self, model):
        self._model = model
        self._last_used = datetime.utcnow()

    def clear(self):
        self._model = None
        self._last_used = None


class ColPaliService:
    MIN_SCORE = 11

    def __init__(
        self,
        model_checkpoint: str = "vidore/colpali-v1.2",
        index_root: str = ".byaldi",
        index_name: str = "listings_index",
        device: str = "mps",
        cache_ttl_seconds: int = 3600,
    ):
        self.index_root = index_root
        self.index_name = index_name
        self.model_checkpoint = model_checkpoint
        self.device = device
        self.model_cache = ModelCache(ttl_seconds=cache_ttl_seconds)
        self.index_root_path = Path(self.index_root)
        self.index_root_path.mkdir(parents=True, exist_ok=True)
        self.mapping_path = self.index_root_path / f"{self.index_name}_mapping.json"
        if not self.mapping_path.exists():
            self._save_mapping({})

    def _save_mapping(self, mapping: Dict[int, int]):
        serialisable = {str(doc_id): listing_id for doc_id, listing_id in mapping.items()}
        with open(self.mapping_path, "w") as f:
            json.dump(serialisable, f)

    def _load_mapping(self) -> Dict[int, int]:
        if not self.mapping_path.exists():
            return {}
        with open(self.mapping_path, "r") as f:
            data = json.load(f)
        return {int(doc_id): listing_id for doc_id, listing_id in data.items()}

    def _get_model(self):
        cached_model = self.model_cache.get()
        if cached_model:
            return cached_model

        index_path = self.index_root_path / self.index_name
        if index_path.exists():
            print(f"Loading existing index from {index_path}")
            model = RAGMultiModalModel.from_index(
                self.index_name,
                index_root=self.index_root,
                device=self.device
            )
            print("Loaded existing ColPali index")
        else:
            print("No existing index found, loading fresh model from pretrained …")
            model = RAGMultiModalModel.from_pretrained(
                self.model_checkpoint,
                device=self.device
            )
            print("ColPali model loaded (no index yet)")

        self.model_cache.set(model)
        return model

    def add_listing_images(self, listing_id: int, images_base64: List[Dict[str, any]]) -> bool:
        """Add images from a listing to the global index, with metadata and mapping."""
        print(f"Adding {len(images_base64)} images for listing {listing_id} to global index")

        model = self._get_model()
        temp_dir = self.index_root_path / f"temp_listing_{listing_id}"
        temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            for idx, img_data in enumerate(images_base64):
                image_bytes = base64.b64decode(img_data['data'])
                image = Image.open(io.BytesIO(image_bytes))
                image_filename = f"listing_{listing_id}_image_{idx}.png"
                image_path = temp_dir / image_filename
                image.save(image_path, 'PNG')

            index_path = self.index_root_path / self.index_name
            index_exists = index_path.exists()

            mapping = self._load_mapping()
            next_doc_id = max(mapping.keys()) + 1 if mapping else 0

            temp_files = sorted(temp_dir.iterdir())
            doc_ids = list(range(next_doc_id, next_doc_id + len(temp_files)))
            metadata_list = [{"listing_id": listing_id} for _ in temp_files]

            if not index_exists:
                model.index(
                    input_path=str(temp_dir),
                    index_name=self.index_name,
                    store_collection_with_index=False,
                    doc_ids=doc_ids,
                    metadata=metadata_list,
                    overwrite=True
                )
                print("Created new index with documents")
            else:
                for file_path, doc_id, metadata in zip(temp_files, doc_ids, metadata_list):
                    model.add_to_index(
                        input_item=str(file_path),
                        store_collection_with_index=False,
                        doc_id=doc_id,
                        metadata=metadata
                    )
                print("Documents added to existing index")

            for doc_id in doc_ids:
                mapping[doc_id] = listing_id
            self._save_mapping(mapping)

            self.model_cache.clear()

            return True
        except Exception as e:
            print(f"Failed to add listing {listing_id} to index: {e}")
            return False
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

    def search(self, query: str, k: int = 10) -> List[Dict]:
        """Search the global index with a natural language query."""
        print(f"Searching global index with query='{query}', k={k}")
        index_path = Path(self.index_root) / self.index_name
        if not index_path.exists():
            print("No index exists yet. Create some listings with images first!")
            return []

        try:
            model = self._get_model()
            results = model.search(query, k=k)
            print(f"Search returned {len(results)} results")

            mapping = self._load_mapping()
            formatted_results = []
            for result in results:
                doc_id = getattr(result, "doc_id", None)
                score = float(getattr(result, "score", 0.0))
                metadata = getattr(result, "metadata", {}) or {}

                if score < self.MIN_SCORE:
                    continue

                lookup_key = doc_id
                if isinstance(doc_id, str):
                    try:
                        lookup_key = int(doc_id)
                    except ValueError:
                        lookup_key = doc_id
                listing_id = mapping.get(lookup_key, None)

                formatted_results.append({
                    "listing_id": listing_id,
                    "score": score,
                    "doc_id": doc_id,
                    "metadata": metadata
                })
                print(f"  Result: doc_id={doc_id}, listing_id={listing_id}, score={score:.4f}")

            return formatted_results
        except Exception as e:
            print(f"Search failed: {e}")
            import traceback
            traceback.print_exc()
            return []

    def get_index_stats(self) -> Dict:
        index_path = Path(self.index_root) / self.index_name
        return {
            "index_exists": index_path.exists(),
            "index_path": str(index_path)
        }

colpali_service = ColPaliService()
