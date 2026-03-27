(function () {
  const petImages = {
    dog: [
      "https://images.unsplash.com/photo-1558788353-f76d92427f16?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1587300003388-59208cc962cb?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1552053831-71594a27632d?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1583337130417-3346a1be7dee?auto=format&fit=crop&w=500&q=80",
    ],
    cat: [
      "https://images.unsplash.com/photo-1592194996308-7b43878e84a6?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1561948955-570b270e7c36?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1494256997604-768d1f608cac?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1478098711619-5ab0b478d6e6?auto=format&fit=crop&w=500&q=80",
    ],
    bird: [
      "https://images.unsplash.com/photo-1552728089-57bdde30beb3?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1452570053594-1b985d6ea890?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1444464666168-49d633b86797?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1530281700549-e82e7bf110d6?auto=format&fit=crop&w=500&q=80",
    ],
    other: [
      "https://images.unsplash.com/photo-1548199973-03cce0bbc87b?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1548802673-380ab8ebc7b7?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1573865526739-10659fec78a5?auto=format&fit=crop&w=500&q=80",
      "https://images.unsplash.com/photo-1517849845537-4d257902454a?auto=format&fit=crop&w=500&q=80",
    ],
  };

  const fallbackImage =
    "https://images.unsplash.com/photo-1517849845537-4d257902454a?auto=format&fit=crop&w=500&q=80";

  window.getPetImageUrl = function (pet) {
    if (pet && typeof pet.imageUrl === "string" && pet.imageUrl.trim() !== "") {
      return pet.imageUrl.trim();
    }
    const species = String((pet && pet.species) || "other").toLowerCase();
    const pool = petImages[species] || petImages.other;
    const numericPart =
      Number(String((pet && pet.id) || "").replace(/\D/g, "")) || 0;
    return pool[numericPart % pool.length];
  };

  window.getPetFallbackImageUrl = function () {
    return fallbackImage;
  };
})();
